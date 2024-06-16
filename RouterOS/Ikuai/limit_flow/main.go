package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

// Config struct to hold configuration data
type Config struct {
	HOST               string `yaml:"host"`
	URI_LOGIN          string `yaml:"uri_login"`
	URI_CALL           string `yaml:"uri_call"`
	Username           string `yaml:"username"`
	Password           string `yaml:"password"`
	Pass               string `yaml:"pass"`
	RememberPassword   string `yaml:"remember_password"`
	ReqDataQueryStatus string `yaml:"req_data_query_status"`
	MAXFLOW            string `yaml:"max_flow"`
	LIMIT_MODEL        string `yaml:"limit_model"`
	LIMIT_UPLOAD       int    `yaml:"limit_upload"`
	LIMIT_DOWNLOAD     int    `yaml:"limit_download"`
	SECONDS            int    `yaml:"seconds"`
	LIMIT_START        string `yaml:"limit_start"`
	LIMIT_END          string `yaml:"limit_end"`
	CLEAR_TIME         string `yaml:"clear_time"`
	INTERFACE_PREFIX   string `yaml:"interface_prefix"`
	LOG_LEVEL          string `yaml:"log_level"`
}

// License struct to hold license information
type License struct {
	Username    string `json:"username"`
	ProductID   string `json:"product_id"`
	IssueDate   string `json:"issue_date"`
	ExpiryDate  string `json:"expiry_date"`
	Permissions string `json:"permissions"`
}

// DecryptLicense function to decrypt the license string
func DecryptLicense(encryptedLicense string, key []byte) (License, error) {
	var license License
	ciphertext, _ := base64.StdEncoding.DecodeString(encryptedLicense)

	block, err := aes.NewCipher(key)
	if err != nil {
		return license, err
	}

	if len(ciphertext) < aes.BlockSize {
		return license, fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	if err := json.Unmarshal(ciphertext, &license); err != nil {
		return license, err
	}

	return license, nil
}

// ValidateLicense function to check if the license is valid
func ValidateLicense(license License) error {
	expiryTime, err := time.Parse(time.RFC3339, license.ExpiryDate)
	if err != nil {
		return fmt.Errorf("invalid license expiry format: %v", err)
	}

	if time.Now().After(expiryTime) {
		return fmt.Errorf("license has expired")
	}

	return nil
}

func calculatePassAndPasswd(config Config, salt string) (string, string) {
	// 计算 password 的 MD5 散列
	md5Hash := md5.New()
	md5Hash.Write([]byte(config.Password))
	passwd := hex.EncodeToString(md5Hash.Sum(nil))

	// 将 salt 和 password 进行拼接并进行 base64 编码
	pass := base64.StdEncoding.EncodeToString([]byte(salt + config.Password))

	return pass, passwd
}

// login function that performs a login and returns the Set-Cookie header value
func login(config Config) (string, error) {
	// Create a custom HTTP client with insecure TLS settings
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	pass, passwd := calculatePassAndPasswd(config, "salt_11")

	// Prepare the login payload
	payload := map[string]string{
		"username":          config.Username,
		"passwd":            passwd,
		"pass":              pass,
		"remember_password": "true",
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	// fmt.Println("payloadBytes:", string(payloadBytes))
	// Create the request
	url := config.HOST + config.URI_LOGIN
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return "", err
	}

	// Set headers
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,zh-TW;q=0.8,en;q=0.7")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	req.Header.Set("DNT", "1")
	req.Header.Set("Origin", config.HOST)
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Referer", config.HOST+"/login")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
	req.Header.Set("sec-ch-ua", `"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"`)
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", `"macOS"`)
	req.Header.Set("sec-gpc", "1")

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Read response body
	if config.LOG_LEVEL == "debug" {
		responseBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("error reading response body.")

		}
		fmt.Println("Response Body:", string(responseBody))
	}
	// Get the Set-Cookie header
	cookies := resp.Header.Get("Set-Cookie")
	if cookies == "" {
		return "", fmt.Errorf("Set-Cookie header not found.")
	}
	if config.LOG_LEVEL == "debug" {
		fmt.Println(cookies)
	}
	// 使用strings.Split函数根据'='分割字符串，然后取第二部分
	parts := strings.Split(cookies, "=")
	if len(parts) > 1 {
		// 再次根据';'分割获取 sess_key 的值，取第一部分
		cookies = strings.Split(parts[1], ";")[0]
		return cookies, nil
	}
	return cookies, nil
}

func getCookies(config Config) []*http.Cookie {
	// Perform login
	cookie, err := login(config)
	if err != nil {
		fmt.Println("Error:", err)
		return nil
	}
	if config.LOG_LEVEL == "debug" {
		fmt.Println("Set-Cookie:", cookie)
	}
	// 创建一个 Cookie 切片
	cookies := []*http.Cookie{
		{Name: "sess_key", Value: cookie},
		{Name: "username", Value: "admin"},
		{Name: "login", Value: "1"},
	}
	return cookies
}

// SetHeaders sets the common headers for the HTTP request
func SetHeaders(config Config, req *http.Request, cookies []*http.Cookie) {
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,zh-TW;q=0.8,en;q=0.7")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	req.Header.Set("DNT", "1")
	req.Header.Set("Origin", config.HOST)
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Referer", config.HOST+"/")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
	req.Header.Set("sec-ch-ua", `"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="99"`)
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", `"macOS"`)
	req.Header.Set("sec-gpc", "1")

	// Set cookies
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
}

// Action Call queries the interface status using the provided URL, cookies, and request data
func ActionCall(config Config, url string, cookies []*http.Cookie, requestData []byte) ([]byte, error) {
	// Create HTTP client with insecure TLS settings
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// Create request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestData))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	// Set common headers
	SetHeaders(config, req, cookies)

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	return responseBody, nil
}

// bytesToSize converts the given bytes into a human-readable string format with units KB, MB, GB, or TB.
func bytesToSize(bytes uint64) string {
	unit := []string{"B", "KB", "MB", "GB", "TB"}
	size := float64(bytes)

	if size == 0 {
		return "0.00 B"
	}

	exponent := math.Floor(math.Log(float64(bytes)) / math.Log(1024))
	suffix := unit[int(exponent)]
	val := math.Floor((size*100)/math.Pow(1024, exponent)) / 100

	return fmt.Sprintf("%.2f%s", val, suffix)
}

// ConvertToBytes converts a string representing size (e.g., "58GB") to bytes.
func ConvertToBytes(sizeStr string) uint64 {
	sizeStr = strings.ToUpper(sizeStr)
	unitMap := map[string]uint64{
		"KB": 1024,
		"MB": 1024 * 1024,
		"GB": 1024 * 1024 * 1024,
		"TB": 1024 * 1024 * 1024 * 1024,
	}

	for unit, multiplier := range unitMap {
		if strings.HasSuffix(sizeStr, unit) {
			valStr := strings.TrimSuffix(sizeStr, unit)
			val, err := strconv.ParseFloat(valStr, 64)
			if err != nil {
				return 0
			}
			return uint64(val * float64(multiplier))
		}
	}
	fmt.Println("unsupported size unit")
	return 0
}

func queryInterfaceFlowStatus(config Config, cookies []*http.Cookie) (map[string]string, error) {
	// 1. 查询端口流量状态
	requestData := []byte(`{"func_name":"monitor_iface","action":"show","param":{"TYPE":"iface_check,iface_stream"}}`)

	responseBody, err := ActionCall(config, config.HOST+config.URI_CALL, cookies, requestData)
	if err != nil {
		fmt.Println("Error querying interface status:", err)
		return nil, err
	}

	// Print response body
	// fmt.Println("Response Body:", string(responseBody))

	// Unmarshal JSON data into a map
	var data map[string]interface{}
	err = json.Unmarshal([]byte(responseBody), &data)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return nil, err
	}

	// Extract and print interface names and total up values for interfaces starting with "netWan"
	ifaceStream, ok := data["Data"].(map[string]interface{})["iface_stream"].([]interface{})
	if !ok {
		fmt.Println("Error accessing iface_stream field")
		return nil, err
	}

	netWanInterfaces := make(map[string]string)
	for _, iface := range ifaceStream {
		ifaceMap, ok := iface.(map[string]interface{})
		if !ok {
			fmt.Println("Error accessing interface field")
			continue
		}
		if ifaceName, ok := ifaceMap["interface"].(string); ok && strings.HasPrefix(ifaceName, config.INTERFACE_PREFIX) {
			totalUp := ifaceMap["total_up"].(float64)
			isOver := uint64(totalUp) > uint64(ConvertToBytes(config.MAXFLOW))
			netWanInterfaces[ifaceName] = fmt.Sprintf("%.f,%s,%t", totalUp, bytesToSize(uint64(totalUp)), isOver)
		}
	}
	if config.LOG_LEVEL == "debug" {
		for iface, flowStatis := range netWanInterfaces {
			fmt.Printf("Interface: %s, FlowStatus: %s\n", iface, flowStatis)
		}
	}
	return netWanInterfaces, err
}

// 查询接口acl状态信息
func queryInterfaceACLStatus(config Config, cookies []*http.Cookie) (map[string]string, error) {

	requestData := []byte(`{"func_name":"simple_qos","action":"show","param":{"TYPE":"data,total","limit":"0,100","ORDER_BY":"","ORDER":""}}`)

	responseBody, err := ActionCall(config, config.HOST+config.URI_CALL, cookies, requestData)
	if err != nil {
		fmt.Println("Error querying interface status:", err)
		return nil, err
	}

	// Print response body
	// fmt.Println("Response Body:", string(responseBody))

	// Unmarshal JSON data into a map
	var data map[string]interface{}
	err = json.Unmarshal([]byte(responseBody), &data)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return nil, err
	}

	// Extract and print interface names and total up values for interfaces starting with "netWan"
	ifaceStream, ok := data["Data"].(map[string]interface{})["data"].([]interface{})
	if !ok {
		fmt.Println("Error accessing iface_stream field")
		return nil, err
	}

	// 创建一个 map 存储 interface 作为 key，enabled 和 id 作为 value
	netWanInterfacesAcl := make(map[string]string)
	for _, iface := range ifaceStream {
		ifaceMap, ok := iface.(map[string]interface{})
		if !ok {
			fmt.Println("Error accessing interface field")
			continue
		}
		if ifaceName, ok := ifaceMap["interface"].(string); ok && strings.HasPrefix(ifaceName, config.INTERFACE_PREFIX) {
			enabled := ifaceMap["enabled"].(string)
			id := ifaceMap["id"].(float64)
			netWanInterfacesAcl[ifaceName] = fmt.Sprintf("%s,%d", enabled, int64(id))
		}
	}

	if config.LOG_LEVEL == "debug" {
		for iface, acl := range netWanInterfacesAcl {
			fmt.Printf("Interface: %s, ACL: %s\n", iface, acl)
		}
	}
	return netWanInterfacesAcl, err
}

// setAclStatus 设置接口的质量服务（QoS）开关。
// 参数:
//
//	action - 开启或关闭 up or down
//	ids - acl规则的id，证书切片 比如 1或者1,2,3。
//
// 返回值:
//
//	错误 - 如果设置过程中发生错误，则返回相应的错误。
func setAclStatus(config Config, cookies []*http.Cookie, action, ids string) error {
	// 构建请求数据
	requestData := []byte(fmt.Sprintf(`{"func_name":"simple_qos","action":"%s","param":{"id":"%s"}}`, action, ids))
	// 发送请求并获取响应
	responseBody, err := ActionCall(config, config.HOST+config.URI_CALL, cookies, requestData)
	if err != nil {
		return fmt.Errorf("error set interface ACL Rule: %w", err)
	}
	// 打印响应体
	fmt.Println("Response Body:", string(responseBody))
	return nil
}

func mergeInterfaceFlowAndACLRules(config Config, cookies []*http.Cookie) (map[string]string, error) {
	// 业务逻辑
	// 1. 端口流量
	if config.LOG_LEVEL == "debug" {
		fmt.Println("Query Flow Status!!!")
	}
	status_map_flow, err := queryInterfaceFlowStatus(config, cookies)
	if err != nil {
		fmt.Println("Error Query Flow Status:", err)
		return nil, err
	}
	// 2. 端口acl规则
	if config.LOG_LEVEL == "debug" {
		fmt.Println("Query ACL Rules!!!")
	}
	status_map_acl, err := queryInterfaceACLStatus(config, cookies)
	if err != nil {
		fmt.Println("Error Query ACL Rules:", err)
		return nil, err
	}
	// 3. 合并查询信息
	for k, v := range status_map_acl {
		if existingValue, exists := status_map_flow[k]; exists {
			status_map_flow[k] = fmt.Sprintf("%s,%s", existingValue, v)
		} else {
			continue
		}
	}
	return status_map_flow, nil
}

func taskMain(config Config) {
	// 登录获取cookie
	cookies := getCookies(config)
	// 查询接口流量、限流状态、acl规则
	netWanInterfaces, err := mergeInterfaceFlowAndACLRules(config, cookies)
	if err != nil {
		log.Fatal("Error merging interface flow and ACL Rules:", err)
		// 或者根据实际情况选择适当的错误处理方式
	}
	// header
	if config.LOG_LEVEL == "debug" {
		fmt.Println("Interface: iface, Info: total_up,total_up_flow,isOver,enable,id")
	}
	// Print netWanInterfaces
	for iface, info := range netWanInterfaces {
		if config.LOG_LEVEL == "debug" || config.LOG_LEVEL == "info" {
			fmt.Printf("Interface: %s, Info: %s\n", iface, info)
		}
		isOver := strings.Split(info, ",")[2]
		enable := strings.Split(info, ",")[3]
		id := strings.Split(info, ",")[4]
		// 流量过大，非限速状态
		if isOver == "true" && enable == "no" {
			setAclStatus(config, cookies, "up", strings.TrimSpace(id))
		}
	}
}

func changeInterfaceACLStatus(config Config, action string) {
	cookies := getCookies(config)
	netWanInterfaces, err := mergeInterfaceFlowAndACLRules(config, cookies)
	if err != nil {
		// 处理错误，比如打印错误日志
		fmt.Println("查询状态失败:", err)
		// 根据实际情况，可以返回错误或进行其他错误处理
		return
	}
	var ids []string // 用于存储所有id
	for _, info := range netWanInterfaces {
		// 假设info是一个map，且包含"id"键
		id := strings.Split(info, ",")[4]
		ids = append(ids, id)
	}

	// 将ids切片转换为以逗号分隔的字符串
	commaSeparatedIds := strings.Join(ids, ",")
	fmt.Println("Comma separated IDs:", commaSeparatedIds)
	setAclStatus(config, cookies, action, commaSeparatedIds)
}

// dailyTask represents the second job that needs to be done daily
func taskLimitStartAll(config Config) {
	fmt.Println("Daily Task Start All Limit executed at:", time.Now())
	changeInterfaceACLStatus(config, "up")
}

// dailyTask represents the second job that needs to be done daily
func taskLimitEndAll(config Config) {
	fmt.Println("Daily Task End All Limit executed at:", time.Now())
	changeInterfaceACLStatus(config, "down")
}

func taskClearFlow(config Config) {
	fmt.Println("Daily Task Clear Flow executed at:", time.Now())
	cookies := getCookies(config)

	// 构建请求数据
	requestData := []byte(`{"func_name":"monitor_iface","action":"clean_statis"}`)

	// 发送请求并获取响应
	responseBody, err := ActionCall(config, config.HOST+config.URI_CALL, cookies, requestData)
	if err != nil {
		fmt.Println("Error Clear interface flow statis.")
	}

	// 打印响应体
	fmt.Println("Response Body:", string(responseBody))
}

// 设置定时任务
func setTimedTasks(config Config) {
	// 定义一个定时器，根据配置的时间间隔执行任务
	ticker := time.NewTicker(time.Duration(config.SECONDS) * time.Second)
	defer ticker.Stop() // 停止定时器

	// 每隔一段时间执行一次任务
	go func() {
		for {
			select {
			case <-ticker.C:
				// 执行间隔定时任务逻辑
				fmt.Printf("执行间隔定时任务,每%d秒\n", config.SECONDS)
				taskMain(config)
			default: // 默认操作，可以根据实际需求进行修改
				// TODO: 循环中的主要逻辑
				continue
			}
		}
	}()

	// 解析每日任务的时间
	taskALLStartTime, err := time.Parse("15:04", config.LIMIT_START)
	if err != nil {
		fmt.Println("解析每日任务-全部限速-时间出错:", err)
		return
	}

	taskAllEndTime, err := time.Parse("15:04", config.LIMIT_END)
	if err != nil {
		fmt.Println("解析每日任务-解除限速-时间出错:", err)
		return
	}

	taskClearTime, err := time.Parse("15:04", config.CLEAR_TIME)
	if err != nil {
		fmt.Println("解析每日任务-清除流量-时间出错:", err)
		return
	}

	// 创建定时器，执行每日任务
	go func() {
		for {
			now := time.Now()
			nextTaskAllStart := time.Date(now.Year(), now.Month(), now.Day(), taskALLStartTime.Hour(), taskALLStartTime.Minute(), 0, 0, now.Location())
			if nextTaskAllStart.Before(now) {
				nextTaskAllStart = nextTaskAllStart.Add(24 * time.Hour)
			}
			taskAllStartDelay := nextTaskAllStart.Sub(now)

			nextTaskAllEnd := time.Date(now.Year(), now.Month(), now.Day(), taskAllEndTime.Hour(), taskAllEndTime.Minute(), 0, 0, now.Location())
			if nextTaskAllEnd.Before(now) {
				nextTaskAllEnd = nextTaskAllEnd.Add(24 * time.Hour)
			}
			taskAllEndDelay := nextTaskAllEnd.Sub(now)

			nextTaskClearStatics := time.Date(now.Year(), now.Month(), now.Day(), taskClearTime.Hour(), taskClearTime.Minute(), 0, 0, now.Location())
			if nextTaskClearStatics.Before(now) {
				nextTaskClearStatics = nextTaskClearStatics.Add(24 * time.Hour)
			}
			taskClearFlowDelay := nextTaskClearStatics.Sub(now)

			select {
			case <-time.After(taskAllStartDelay):
				// 执行每日任务-全部限速-逻辑
				fmt.Println("执行每日任务-全部限速")
				taskLimitStartAll(config)
			case <-time.After(taskAllEndDelay):
				// 执行每日任务-解除限速-逻辑
				fmt.Println("执行每日任务-解除限速")
				taskLimitEndAll(config)
			case <-time.After(taskClearFlowDelay):
				// 执行每日任务-清除流量统计-逻辑
				fmt.Println("执行每日任务-清除流量统计")
				taskClearFlow(config)
			}
		}
	}()

	// 阻塞主 goroutine，保持程序运行
	select {}
}

// Function to handle API requests with an internal parameter
func apiHandler(message string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the "name" query parameter
		name := r.URL.Query().Get("name")
		if name == "" {
			name = "world"
		}
		fmt.Fprintf(w, "Hello, %s! \n%s", name, message)
	}
}

func checkLicense() string {
	// Decrypt and validate license
	// License文件名为"license"
	licenseFile := "license"
	// 使用ioutil.ReadFile读取整个文件内容
	content, err := ioutil.ReadFile(licenseFile)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}
	encryptionKey := []byte("K67tJXm88Fq82DkP") // Replace with your actual key

	licenseResult := ""
	license, err := DecryptLicense(string(content), encryptionKey)
	if err != nil {
		licenseResult = "License decryption failed"
		fmt.Println("Error decrypting license:", err)
	}

	err = ValidateLicense(license)
	if err != nil {
		licenseResult = "License validation failed"
		fmt.Println("License validation failed:", err)
	}

	if err == nil {
		licenseResult = fmt.Sprintf("License is valid. User:%s\nLicense is valid. ExpriyDate:%s", license.Username, license.ExpiryDate)
	}
	fmt.Println(licenseResult)
	return licenseResult
}

func main() {
	// Read configuration from file
	configFile, err := os.Open("config.yaml")
	if err != nil {
		fmt.Println("Error opening config file:", err)
		return
	}
	defer configFile.Close()

	byteValue, err := ioutil.ReadAll(configFile)
	if err != nil {
		fmt.Println("Error reading config file:", err)
		return
	}

	var config Config
	err = yaml.Unmarshal(byteValue, &config)
	if err != nil {
		fmt.Println("Error parsing config file:", err)
		return
	}

	licenseResult := checkLicense()

	if strings.HasPrefix(licenseResult, "License is valid") {
		// 启动定时任务
		taskMain(config)

		// 设置定时任务
		setTimedTasks(config)
	} else {
		fmt.Println("License is not valid. Exiting...")
		// Set up the API handler
		http.HandleFunc("/api", apiHandler(licenseResult))
		// Start the HTTP server
		fmt.Println("Starting server at :8088")
		if err := http.ListenAndServe(":8088", nil); err != nil {
			fmt.Println("Failed to start server:", err)
		}
	}
}
