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
)

func GetUrls() []string {
	file, err := os.Open("./vulnerable_urls.txt")
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

func main() {
	fmt.Println("Starting Clickjacking scanner")
	maxWorkers := 20
	jobs := make(chan string)
	ch := make(chan string)
	var wg sync.WaitGroup
	urls := GetUrls()
	var vulnerableUrls []string
	client := &http.Client{
		Timeout: time.Second * 5,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	fmt.Println("Got ", len(urls), "URLs to check.")
	for workers := 1; workers <= maxWorkers; workers++ {
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
}
