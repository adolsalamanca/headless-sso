package main

import (
	"bufio"
	"context"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/theckman/yacspin"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
)

// Time before MFA step times out
const MFA_TIMEOUT = 30

var cfg = yacspin.Config{
	Frequency:         100 * time.Millisecond,
	CharSet:           yacspin.CharSets[59],
	Suffix:            "AWS SSO Signing in: ",
	SuffixAutoColon:   false,
	Message:           "",
	StopCharacter:     "✓",
	StopFailCharacter: "✗",
	StopMessage:       "Logged in successfully",
	StopFailMessage:   "Log in failed",
	StopColors:        []string{"fgGreen"},
}

var spinner, _ = yacspin.New(cfg)

func main() {
	spinner.Start()
	url := getURL()
	login_new(url)
}

// returns sso url from stdin.
func getURL() string {
	spinner.Message("reading url from stdin")

	scanner := bufio.NewScanner(os.Stdin)
	url := ""
	for url == "" {
		scanner.Scan()
		t := scanner.Text()
		r, _ := regexp.Compile("^https.*user_code=([A-Z]{4}-?){2}")

		if r.MatchString(t) {
			url = t
		}
	}

	fmt.Printf("url: %s\n", url)

	return url
}

func login_new(url string) {
	spinner.Message(color.MagentaString("init headless-browser \n"))
	spinner.Pause()

	browser := rod.New().MustConnect().NoDefaultDevice()
	loadCookies(*browser)

	p := browser.MustPage(url).MustWindowFullscreen()
	ctx, cancel := context.WithCancel(context.Background())
	page := p.Context(ctx)

	go func() {
		time.Sleep(1 * time.Minute)
		cancel()
	}()

	// Google part
	page.MustWaitStable().MustScreenshot("sso1.png")
	r, err2 := page.ElementR("button", "Confirm and continue")
	if err2 != nil {
		fmt.Println("didn't find the button")
	} else {
		fmt.Println("don't need the rest of steps, cookies are stored")
		r.MustClick()
		page.MustWaitStable().MustScreenshot("sso1.png")
	}

	page.MustElement("#identifierId").MustWaitVisible().MustInput("adolfo@timescale.com")
	page.MustElement("#identifierNext").MustWaitEnabled().MustClick()

	// page.MustElementR("button", "Next").MustClick()
	page.MustWaitStable().MustScreenshot("sso2.png")
	page.MustElement(`input[type="password"]`).MustWaitVisible().MustInput("Wolverhampton1")
	page.MustElement("#passwordNext").MustWaitEnabled().MustClick()

	page.MustWaitStable().MustScreenshot("sso3.png")

	page.MustElementR("div", "Google Authenticator").MustClick()
	page.MustWaitStable().MustScreenshot("sso4.png")

	// otp is an alias to a command using a tool that generates one time passwords, totp timescale in my case.
	cmd, builder := exec.Command("/usr/local/bin/totp", "timescale"), new(strings.Builder)
	cmd.Stdout = builder
	err := cmd.Run()
	if err != nil {
		panic(fmt.Sprintf("could not run otp command, %s", err))
	}

	page.MustElement(`input[type="tel"]`).MustWaitVisible().MustInput(builder.String())
	page.MustElement("#totpNext").MustWaitEnabled().MustClick()

	page.MustWaitStable().MustScreenshot("sso5.png")

	// AWS part
	page.MustElement("#cli_verification_btn").MustClick()
	page.MustWaitStable().MustScreenshot("sso6.png")

	debugPageElements(page)

	defer browser.MustClose()

	saveCookies(*browser)
}

// load cookies
func loadCookies(browser rod.Browser) {
	spinner.Message("loading cookies")
	dirname, err := os.UserHomeDir()
	if err != nil {
		error(err.Error())
	}

	data, _ := os.ReadFile(dirname + "/.headless-sso")
	sEnc, _ := b64.StdEncoding.DecodeString(string(data))
	var cookie *proto.NetworkCookie
	json.Unmarshal(sEnc, &cookie)

	if cookie != nil {
		browser.MustSetCookies(cookie)
	}
}

// save authn cookie
func saveCookies(browser rod.Browser) {
	dirname, err := os.UserHomeDir()
	if err != nil {
		error(err.Error())
	}

	cookies := browser.MustGetCookies()

	for _, cookie := range cookies {
		if cookie.Name == "x-amz-sso_authn" {
			data, _ := json.Marshal(cookie)

			sEnc := b64.StdEncoding.EncodeToString([]byte(data))
			err = os.WriteFile(dirname+"/.headless-sso", []byte(sEnc), 0644)

			if err != nil {
				error("Failed to save x-amz-sso_authn cookie")
			}
			break
		}
	}
}

// print error message and exit
func panic(errorMsg string) {
	red := color.New(color.FgRed).SprintFunc()
	spinner.StopFailMessage(red("Login failed error - " + errorMsg))
	spinner.StopFail()
	os.Exit(1)
}

// print error message
func error(errorMsg string) {
	yellow := color.New(color.FgYellow).SprintFunc()
	spinner.Message("Warn: " + yellow(errorMsg))
}

func debugPageElements(page *rod.Page) {
	fmt.Println("=== PAGE ELEMENT DEBUG ===")

	// Take a screenshot first
	page.MustScreenshot("debug_current_page.png")
	fmt.Println("Screenshot saved as debug_current_page.png")

	// Get page title and URL
	fmt.Printf("Page Title: %s\n", page.MustInfo().Title)
	fmt.Printf("Page URL: %s\n", page.MustInfo().URL)

	// Find all form-related elements
	formElements := page.MustElements("input, button, select, textarea")
	fmt.Printf("\nFound %d form elements total\n", len(formElements))

	for i, el := range formElements {
		tagName := el.MustEval("() => this.tagName").String()
		fmt.Printf("\n--- Element %d (%s) ---\n", i, tagName)

		// Common attributes for all elements
		attrs := []string{"id", "name", "class", "type", "placeholder", "aria-label", "value"}
		for _, attr := range attrs {
			if val, err := el.Attribute(attr); err == nil && val != nil && *val != "" {
				fmt.Printf("%s: %s\n", attr, *val)
			}
		}

		// Get text content
		text := el.MustText()
		if text != "" {
			fmt.Printf("Text: '%s'\n", text)
		}

		// Get visibility and position info
		visible := el.MustVisible()
		fmt.Printf("Visible: %t\n", visible)

		if visible {
			box := el.MustShape().Box()
			fmt.Printf("Position: x=%f, y=%f, width=%f, height=%f\n",
				box.X, box.Y, box.Width, box.Height)
		}

		// Get the HTML
		html, _ := el.HTML()
		fmt.Printf("HTML: %s\n", html)
	}
}
