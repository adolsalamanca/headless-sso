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

const (
	MfaTimeoutSeconds = 90
	ssoCookiePath     = "/.headless-sso"
)

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
	// TODO: Try the step Confirm and Continue at start, might be already the required one.
	spinner.Start()
	url := getURL()
	loginNew(url)
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

func loginNew(url string) {
	spinner.Message(color.MagentaString("init headless-browser \n"))
	spinner.Pause()

	browser := rod.New().MustConnect().NoDefaultDevice()
	loadCookies(*browser)

	p := browser.MustPage(url).MustWindowFullscreen()
	ctx, cancel := context.WithCancel(context.Background())
	page := p.Context(ctx)

	go func() {
		time.Sleep(MfaTimeoutSeconds * time.Second)
		cancel()
	}()

	defer browser.MustClose()
	page.MustWaitStable().MustScreenshot("sso1.png")
	// Google Auth
	// MustInput replace xxx by Username
	page.MustElement("#identifierId").MustWaitVisible().MustInput("xxx")
	page.MustElement("#identifierNext").MustWaitEnabled().MustClick()

	page.MustWaitStable().MustScreenshot("sso2.png")
	// MustInput replace yyy by Password
	page.MustElement(`input[type="password"]`).MustWaitVisible().MustInput("yyy")
	page.MustElement("#passwordNext").MustWaitEnabled().MustClick()

	page.MustElementR("div", "Google Authenticator").MustWaitEnabled().MustClick()
	page.MustWaitStable().MustScreenshot("sso3.png")

	// otp is an alias to a command using a tool that generates one time passwords, totp timescale in my case.
	builder := new(strings.Builder)
	cmd := exec.Command("/usr/local/bin/totp", "timescale")
	cmd.Stdout = builder
	err := cmd.Run()
	if err != nil {
		printPanic(fmt.Sprintf("could not run otp command, %s", err))
	}

	debugPageElements(page)

	page.MustElement(`input[type="tel"]`).MustWaitVisible().MustInput(builder.String())
	page.MustElement("#totpNext").MustWaitEnabled().MustClick()

	// Insert otp
	page.MustWaitStable().MustScreenshot("sso4.png")

	// AWS confirmation
	page.MustElementR("button", "Confirm and continue").MustClick()
	page.MustWaitStable().MustScreenshot("ssoPreFinal.png")

	page.MustElementR("button", "Allow access").MustWaitEnabled().MustClick()
	page.MustWaitStable().MustScreenshot("ssoFinal.png")

	saveCookies(*browser)
}

// load cookies
func loadCookies(browser rod.Browser) {
	spinner.Message("loading cookies")
	homeDir, err := os.UserHomeDir()
	if err != nil {
		printError(err.Error())
	}

	data, _ := os.ReadFile(homeDir + ssoCookiePath)
	sEnc, _ := b64.StdEncoding.DecodeString(string(data))
	var cookie *proto.NetworkCookie
	err = json.Unmarshal(sEnc, &cookie)
	if err != nil {
		printError(err.Error())
	}

	if cookie != nil {
		browser.MustSetCookies(cookie)
	}
}

// save authn cookie
func saveCookies(browser rod.Browser) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		printError(err.Error())
	}

	cookies := browser.MustGetCookies()

	for _, cookie := range cookies {
		if cookie.Name == "x-amz-sso_authn" {
			data, _ := json.Marshal(cookie)

			sEnc := b64.StdEncoding.EncodeToString(data)
			err = os.WriteFile(homeDir+ssoCookiePath, []byte(sEnc), 0644)

			if err != nil {
				printError("Failed to save x-amz-sso_authn cookie")
			}
			break
		}
	}
}

// print error message and exit
func printPanic(errorMsg string) {
	red := color.New(color.FgRed).SprintFunc()
	spinner.StopFailMessage(red("Login failed error - " + errorMsg))
	spinner.StopFail()
	os.Exit(1)
}

// print error message
func printError(errorMsg string) {
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
