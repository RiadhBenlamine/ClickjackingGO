package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/urfave/cli/v2"
)

func GetUrls(pathUrls string) []string {
	file, err := os.Open(pathUrls)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var urls []string
	for scanner.Scan() {
		urls = append(urls, scanner.Text())
	}
	return urls
}
func Check(url string, client *http.Client, c chan<- string) {
	resp, err := client.Get(url)
	if err != nil {
		return
	}

	defer resp.Body.Close()

	XfoSecure := false
	CspSecure := false
	XfoHeader := resp.Header.Values("X-Frame-Options")
	CspHeader := resp.Header.Values("Content-Security-Policy")
	for _, value := range XfoHeader {
		if strings.Contains(value, "SAMEORIGIN") || strings.Contains(value, "DENY") {
			XfoSecure = true
		}
	}
	for _, value := range CspHeader {
		value = strings.ToLower(value)
		if strings.Contains(value, "frame-ancestors") {

			CspSecure = true
		}
	}
	if !XfoSecure || !CspSecure {
		c <- url
	}

}
func worker(jobs <-chan string, ch chan<- string, client *http.Client, wg *sync.WaitGroup) {
	defer wg.Done()
	for url := range jobs {
		Check(url, client, ch)
	}
}

type Config struct {
	PathUrls   string
	MaxWorkers int
	Timeout    int
	OutputFile string
}

func main() {
	config := &Config{}
	cmd := &cli.App{
		Flags: []cli.Flag{
			&cli.PathFlag{
				Name:     "list",
				Usage:    "List of URLs to scan",
				Required: true,
				Value:    "",
				Aliases:  []string{"l"},
			},
			&cli.IntFlag{
				Name:    "threads",
				Aliases: []string{"t"},
				Value:   10,
				Usage:   "Number of threads",
			},
			&cli.IntFlag{
				Name:    "timeout",
				Aliases: []string{"T"},
				Value:   30,
				Usage:   "Timeout in seconds",
			},
			&cli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Value:   "",
				Usage:   "Output file",
			},
		},
		Action: func(c *cli.Context) error {
			config.MaxWorkers = c.Int("threads")
			config.Timeout = c.Int("timeout")
			config.OutputFile = c.String("output")
			config.PathUrls = c.Path("list")

			return nil
		},
	}
	if err := cmd.Run(os.Args); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Starting Clickjacking scanner")
	jobs := make(chan string)
	ch := make(chan string)
	var wg sync.WaitGroup
	urls := GetUrls(config.PathUrls)
	var vulnerableUrls []string
	client := &http.Client{
		Timeout: time.Second * time.Duration(config.Timeout),
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	fmt.Println("Got ", len(urls), "URLs to check.")
	for workers := 1; workers <= config.MaxWorkers; workers++ {
		wg.Add(1)
		go worker(jobs, ch, client, &wg)

	}
	go func() {
		defer close(jobs)

		for _, url := range urls {
			jobs <- url
		}
	}()

	go func() {
		wg.Wait()
		close(ch)
	}()
	for url := range ch {
		vulnerableUrls = append(vulnerableUrls, url)
		fmt.Println(url)
	}

	fmt.Println("[+] Total vulnerabilities: ", len(vulnerableUrls))
	fmt.Println("Finished Clickjacking scanner")
	if config.OutputFile != "" {
		f, err := os.Create(config.OutputFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		w := bufio.NewWriter(f)
		for _, url := range vulnerableUrls {
			_, err := fmt.Fprintln(w, url)
			if err != nil {
				return
			}
		}
		if err := w.Flush(); err != nil {
			log.Fatal(err)
		}
	}
}
