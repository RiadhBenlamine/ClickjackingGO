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
func Check(url string, c chan<- string) {
	client := &http.Client{
		Timeout: time.Second * 5,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK && strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		_, hasXFrame := resp.Header["X-Frame-Options"]
		_, hasCSP := resp.Header["Content-Security-Policy"]
		if !hasXFrame && !hasCSP {
			c <- url
		}
	}

}

func main() {
	ch := make(chan string)
	var wg sync.WaitGroup
	urls := GetUrls()

	fmt.Println("Starting Clickjacking scanner")
	fmt.Println("Got ", len(urls), "urls to check.")
	for _, url := range urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			Check(url, ch)
		}(url)
	}
	go func() {
		wg.Wait()
		close(ch)
	}()
	for url := range ch {
		fmt.Println(url)
	}
	fmt.Println("Finished Clickjacking scanner")
}
