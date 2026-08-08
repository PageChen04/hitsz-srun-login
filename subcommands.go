package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

// ---------------------------------------------------------------------------
// local-login: authenticate the current machine via srun portal local user
// ---------------------------------------------------------------------------

func runLocalLogin(args []string) {
	fs := flag.NewFlagSet("local-login", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s local-login [options]\n\nOptions:\n", os.Args[0])
		fs.PrintDefaults()
	}

	var username, password, ip, sessionFile string
	var noSession, nonInteractive bool

	fs.StringVar(&username, "username", "", "Local portal username")
	fs.StringVar(&password, "password", "", "Local portal password")
	fs.StringVar(&ip, "ip", "", "IP address to authenticate (default: auto-detected by server)")
	fs.StringVar(&sessionFile, "session-file", defaultSessionFile(), "Path to persisted session cookies")
	fs.BoolVar(&noSession, "no-session", false, "Disable loading and saving persisted session cookies")
	fs.BoolVar(&nonInteractive, "non-interactive", false, "Fail instead of prompting for missing values")
	fs.Parse(args)

	if noSession {
		sessionFile = ""
	} else {
		log.Printf("Session file: %s", sessionFile)
	}

	input := bufio.NewReader(os.Stdin)

	var err error
	if username == "" {
		username, err = promptInput(input, os.Stdout, "local username: ", "username", nonInteractive)
		if err != nil {
			log.Fatal(err)
		}
	}
	if password == "" {
		password, err = promptInput(input, os.Stdout, "local password: ", "password", nonInteractive)
		if err != nil {
			log.Fatal(err)
		}
	}

	client, jar := newHttpClient("", sessionFile)

	result, err := srunLocalLogin(username, password, ip, client)
	if err != nil {
		log.Fatal("Local login failed: ", err)
	}
	if err := jar.Save(); err != nil {
		log.Printf("Save session: %v", err)
	}
	if result.Error != "ok" {
		log.Fatalf("Login error: %s (ecode=%d, msg=%s)", result.Error, result.ECode, result.PloyMsg)
	}
	log.Printf("Login successful: %s", result.PloyMsg)
	if result.Online != "" {
		log.Printf("Online IP: %s", result.Online)
	}
}

// ---------------------------------------------------------------------------
// logout: deauthenticate current machine from campus network (rad_user_dm)
// ---------------------------------------------------------------------------

func runLogout(args []string) {
	fs := flag.NewFlagSet("logout", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s logout [options]\n\nOptions:\n", os.Args[0])
		fs.PrintDefaults()
	}

	var username, ip, sessionFile string
	var noSession, nonInteractive bool

	fs.StringVar(&username, "username", "", "Username currently authenticated (required)")
	fs.StringVar(&ip, "ip", "", "IP address to log out (required)")
	fs.StringVar(&sessionFile, "session-file", defaultSessionFile(), "Path to persisted session cookies")
	fs.BoolVar(&noSession, "no-session", false, "Disable loading and saving persisted session cookies")
	fs.BoolVar(&nonInteractive, "non-interactive", false, "Fail instead of prompting for missing values")
	fs.Parse(args)

	if noSession {
		sessionFile = ""
	}

	// Resolve missing username/ip from rad_user_info if possible.
	client, jar := newHttpClient("", sessionFile)

	if ip == "" || username == "" {
		log.Printf("Querying current online status to fill missing username/ip...")
		info, err := srunGetUserInfo("", client)
		if err != nil {
			log.Printf("rad_user_info failed: %v", err)
		} else if info.Error == "ok" {
			if ip == "" {
				ip = info.IP
				log.Printf("Resolved IP: %s", ip)
			}
			if username == "" {
				username = info.Username
				log.Printf("Resolved username: %s", username)
			}
		}
	}

	if ip == "" {
		log.Fatal("Cannot determine IP to log out; specify with -ip")
	}
	if username == "" {
		log.Fatal("Cannot determine username; specify with -username")
	}

	result, err := srunLogout(username, ip, client)
	if err != nil {
		log.Fatal("Logout failed: ", err)
	}
	if err := jar.Save(); err != nil {
		log.Printf("Save session: %v", err)
	}
	log.Printf("Logout result: error=%q ecode=%d msg=%q", result.Error, result.ECode, result.SucMsg)
}

// ---------------------------------------------------------------------------
// list-devices: list all authenticated devices for the account
// ---------------------------------------------------------------------------

func runListDevices(args []string) {
	fs := flag.NewFlagSet("list-devices", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s list-devices [options]\n\nOptions:\n", os.Args[0])
		fs.PrintDefaults()
	}

	var username, password, captcha, sessionFile string
	var noSession, nonInteractive bool

	fs.StringVar(&username, "username", "", "Self-service portal username")
	fs.StringVar(&password, "password", "", "Self-service portal password")
	fs.StringVar(&captcha, "captcha", "", "Self-service portal captcha code (prompted from image if empty)")
	fs.StringVar(&sessionFile, "session-file", defaultSessionFile(), "Path to persisted session cookies")
	fs.BoolVar(&noSession, "no-session", false, "Disable loading and saving persisted session cookies")
	fs.BoolVar(&nonInteractive, "non-interactive", false, "Fail instead of prompting for missing values")
	fs.Parse(args)

	if noSession {
		sessionFile = ""
	} else {
		log.Printf("Session file: %s", sessionFile)
	}

	client, jar := newHttpClient("", sessionFile)

	// Ensure portal session (reuse → SSO jump → credentials).
	if _, err := ensurePortalSession(username, password, captcha, sessionFile, nonInteractive, client, jar); err != nil {
		log.Fatal("Portal login failed: ", err)
	}

	devices, err := listOnlineDevices(client)
	if err != nil {
		log.Fatal("List devices failed: ", err)
	}

	if len(devices) == 0 {
		fmt.Println("No devices online.")
		return
	}

	// Print table.
	fmt.Printf("%-12s  %-15s  %-19s  %-19s  %-15s  %s\n",
		"ID", "IP", "MAC", "Login Time", "Product", "Duration")
	fmt.Println(strings.Repeat("-", 100))
	for _, d := range devices {
		fmt.Printf("%-12s  %-15s  %-19s  %-19s  %-15s  %s\n",
			d.RadOnlineID, d.IP, d.MAC, d.LoginTime, d.Product, d.Duration)
	}
}

// ---------------------------------------------------------------------------
// kick-device: force a device offline via the self-service portal
// ---------------------------------------------------------------------------

func runKickDevice(args []string) {
	fs := flag.NewFlagSet("kick-device", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s kick-device [options]\n\nOptions:\n", os.Args[0])
		fs.PrintDefaults()
	}

	var username, password, captcha, sessionFile, deviceID, deviceMAC string
	var noSession, nonInteractive bool

	fs.StringVar(&username, "username", "", "Self-service portal username")
	fs.StringVar(&password, "password", "", "Self-service portal password")
	fs.StringVar(&captcha, "captcha", "", "Self-service portal captcha code (prompted from image if empty)")
	fs.StringVar(&deviceID, "id", "", "Device rad_online_id to kick (from list-devices)")
	fs.StringVar(&deviceMAC, "mac", "", "Device MAC address to kick (from list-devices)")
	fs.StringVar(&sessionFile, "session-file", defaultSessionFile(), "Path to persisted session cookies")
	fs.BoolVar(&noSession, "no-session", false, "Disable loading and saving persisted session cookies")
	fs.BoolVar(&nonInteractive, "non-interactive", false, "Fail instead of prompting for missing values")
	fs.Parse(args)

	if deviceID == "" || deviceMAC == "" {
		fmt.Fprintf(os.Stderr, "Error: -id and -mac are required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if noSession {
		sessionFile = ""
	} else {
		log.Printf("Session file: %s", sessionFile)
	}

	client, jar := newHttpClient("", sessionFile)

	// Ensure portal session, get CSRF.
	csrfToken, err := ensurePortalSession(username, password, captcha, sessionFile, nonInteractive, client, jar)
	if err != nil {
		log.Fatal("Portal login failed: ", err)
	}

	if err := kickDevice(deviceID, deviceMAC, csrfToken, client); err != nil {
		log.Fatal("Kick device failed: ", err)
	}
	if err := jar.Save(); err != nil {
		log.Printf("Save session: %v", err)
	}
	log.Printf("Device %s (%s) kicked successfully.", deviceID, deviceMAC)
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// ensurePortalSession guarantees an authenticated self-service portal session
// and returns its /home CSRF token. Order of attempts:
//
//  1. Reuse an already-valid session cookie (tryExistingPortalSession).
//  2. When no credentials were supplied, jump via the main portal's
//     "Self Service" SSO endpoint (no password needed) if the campus network
//     is already authenticated for the current IP.
//  3. Fall back to the username/password form login (may require a captcha).
//
// When the form login fails because a captcha is required, the session cookies
// are persisted anyway (jar.Save) so the pending captcha — which is bound to
// that server-side session — can be reused by a follow-up run with -captcha.
func ensurePortalSession(username, password, captcha, sessionFile string, nonInteractive bool,
	client *http.Client, jar *persistentCookieJar) (string, error) {
	csrfToken, ok, err := tryExistingPortalSession(client)
	if err != nil {
		log.Printf("Checking existing portal session: %v", err)
	}

	if !ok && username == "" && password == "" {
		csrfToken, ok, err = tryPortalSSO(client)
		if err != nil {
			log.Printf("Portal SSO jump: %v", err)
		}
		if ok {
			log.Print("Portal SSO jump succeeded (no password needed)")
			if err := jar.Save(); err != nil {
				log.Printf("Save session: %v", err)
			}
			return csrfToken, nil
		}
	}

	if !ok {
		username, password = requirePortalCredentials(username, password, nonInteractive)
		csrfToken, err = selfServiceLogin(username, password, captcha, nonInteractive,
			bufio.NewReader(os.Stdin), os.Stdout, client, sessionFile)
		if err != nil {
			// Persist the pending session even on failure: without it, a
			// non-interactive -captcha follow-up run starts a fresh session
			// with a different captcha and can never succeed.
			if saveErr := jar.Save(); saveErr != nil {
				log.Printf("Save session: %v", saveErr)
			}
			return "", err
		}
		if err := jar.Save(); err != nil {
			log.Printf("Save session: %v", err)
		}
	}
	return csrfToken, nil
}

// requirePortalCredentials prompts for username/password if not provided.
func requirePortalCredentials(username, password string, nonInteractive bool) (string, string) {
	log.Printf("[i] You need to log in to the self service portal to proceed. If you do not have a local account, try login with HIT SSO before trying this command.")
	input := bufio.NewReader(os.Stdin)
	var err error
	if username == "" {
		username, err = promptInput(input, os.Stdout, "local username: ", "username", nonInteractive)
		if err != nil {
			log.Fatal(err)
		}
	}
	if password == "" {
		password, err = promptInput(input, os.Stdout, "local password: ", "password", nonInteractive)
		if err != nil {
			log.Fatal(err)
		}
	}
	return username, password
}
