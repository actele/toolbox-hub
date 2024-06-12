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
	"math/rand"
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
		return "", fmt.Errorf("Set-Cookie header not found")
	}
	fmt.Println(cookies)
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

	fmt.Println("Set-Cookie:", cookie)
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

// ByteCountSI formats a byte count to a human-readable string with SI units.
func ByteCountSI(b float64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%.0f B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", b/float64(div), "kMGTPE"[exp])
}

// ConvertToBytes converts a string representing size (e.g., "58GB") to bytes.
func ConvertToBytes(sizeStr string) (uint64, error) {
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
				return 0, err
			}
			return uint64(val * float64(multiplier)), nil
		}
	}

	return 0, fmt.Errorf("unsupported size unit")
}

// IsOverThreshold checks if totalBytes exceeds the threshold.
func IsOverThreshold(totalBytes uint64, thresholdStr string) (bool, error) {
	thresholdBytes, err := ConvertToBytes(thresholdStr)
	if err != nil {
		return false, err
	}
	fmt.Println("isOver:", totalBytes, thresholdBytes, totalBytes > thresholdBytes)
	return totalBytes > thresholdBytes, nil
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
			if totalUp, ok := ifaceMap["total_up"].(float64); ok {
				//
				isOver, err := IsOverThreshold(uint64(totalUp), config.MAXFLOW)
				if err != nil {
					// 处理错误，例如记录日志、返回错误信息等
					// 这里选择忽略错误，仅作为演示
					continue
				}
				netWanInterfaces[ifaceName] = fmt.Sprintf("%.0f,%s,%t", totalUp, ByteCountSI(totalUp), isOver)
			}
		}
	}
	if config.LOG_LEVEL == "debug" {
		for iface, qosStatus := range netWanInterfaces {
			fmt.Printf("Interface: %s, QosStatus: %s\n", iface, qosStatus)
		}
	}
	return netWanInterfaces, err
}

// generateRandomEightDigitNumber 生成一个8位随机数字。
// 该函数使用时间戳作为随机数生成器的种子，以确保每次调用时都能得到不同的随机数。
// 返回的随机数在10000000到99999999之间，保证了数字的长度为8位。
func generateRandomEightDigitNumber() int {
	// 使用当前时间的纳秒级戳作为随机数生成器的种子
	rand.Seed(time.Now().UnixNano())
	// 生成一个0到90000000之间的随机数，然后加上10000000，以确保数字在10000000到99999999之间
	return rand.Intn(90000000) + 10000000
}

// setQosSwitch 设置接口的质量服务（QoS）开关。
// 参数:
//
//	parent - 父接口名称。
//	iface - 需要设置QoS开关的接口名称。
//	qosSwitch - QoS开关的设置值，通常为0或1，0表示关闭，1表示打开。
//
// 返回值:
//
//	错误 - 如果设置过程中发生错误，则返回相应的错误。
func setQosSwitch(config Config, cookies []*http.Cookie, parent, iface string, qosSwitch int) error {
	// 构建请求数据
	requestData := []byte(fmt.Sprintf(`{"func_name":"layer7_intell","action":"set_iface","param":{"parent":"%s","interface":"%s","upload":%d,"download":%d,"qos_switch":%d,"comment":"","id":%08d}}`, parent, iface, config.LIMIT_UPLOAD, config.LIMIT_DOWNLOAD, qosSwitch, generateRandomEightDigitNumber()))

	// 发送请求并获取响应
	responseBody, err := ActionCall(config, config.HOST+config.URI_CALL, cookies, requestData)
	if err != nil {
		return fmt.Errorf("error set interface Qos: %w", err)
	}

	// 打印响应体
	fmt.Println("Response Body:", string(responseBody))
	return nil
}

func queryInterfaceQosStatus(config Config, cookies []*http.Cookie) (map[string]string, error) {
	// 构建请求数据
	requestData := []byte(`{"func_name":"layer7_intell","action":"show","param":{"TYPE":"iface_bandwidth,data","limit":"0,200","ORDER_BY":"","ORDER":""}}`)

	// 发送请求并获取响应
	responseBody, err := ActionCall(config, config.HOST+config.URI_CALL, cookies, requestData)
	if err != nil {
		fmt.Println("Error querying interface qos status")
		return nil, err
	}

	// 打印响应体
	// fmt.Println("Response Body:", string(responseBody))
	var data map[string]interface{}
	err = json.Unmarshal(responseBody, &data)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling JSON: %w", err)
	}

	ifaceBandwidth, ok := data["Data"].(map[string]interface{})["iface_bandwidth"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("error accessing iface_bandwidth field")
	}

	netWanInterfaces := make(map[string]string)
	for _, iface := range ifaceBandwidth {
		ifaceMap, ok := iface.(map[string]interface{})
		if !ok {
			fmt.Println("Error accessing interface field")
			continue
		}
		if ifaceName, ok := ifaceMap["interface"].(string); ok && strings.HasPrefix(ifaceName, config.INTERFACE_PREFIX) {
			parent := ifaceMap["parent"].(string)
			upload := ifaceMap["upload"].(float64)
			download := ifaceMap["download"].(float64)
			qosSwitch := ifaceMap["qos_switch"].(float64)
			comment := ifaceMap["comment"].(string)
			netWanInterfaces[ifaceName] = fmt.Sprintf("%s,%.0f,%.0f,%.0f,%s",
				parent, upload, download, qosSwitch, comment)
		}
	}
	// Print netWanInterfaces
	if config.LOG_LEVEL == "debug" {
		for iface, qosStatus := range netWanInterfaces {
			fmt.Printf("Interface: %s, QosStatus: %s\n", iface, qosStatus)
		}
	}
	return netWanInterfaces, nil
}

func mergeInterfaceFlowAndQosStatus(config Config, cookies []*http.Cookie) (map[string]string, error) {
	// 业务逻辑
	// 1.端口流量
	status_map_flow, err := queryInterfaceFlowStatus(config, cookies)
	if err != nil {
		fmt.Println("Error Query Flow Status:", err)
		return nil, err
	}
	// 2. 端口限速情况
	status_map_qos, err := queryInterfaceQosStatus(config, cookies)
	if err != nil {
		fmt.Println("Error Query QOS Status:", err)
		return nil, err
	}
	// 3. 合并两个查询信息
	for k, v := range status_map_qos {
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
	// 查询接口流量和限流状态
	wanInterfaces, err := mergeInterfaceFlowAndQosStatus(config, cookies)
	if err != nil {
		log.Fatal("Error merging interface flow and QoS status:", err)
		// 或者根据实际情况选择适当的错误处理方式
	}
	// header
	fmt.Println("Interface: iface, Info: total_up,total_up_flow,isOver,parent,limit_upload,limit_download,qos_stat,comment")
	// Print netWanInterfaces
	for iface, info := range wanInterfaces {
		if config.LOG_LEVEL == "debug" || config.LOG_LEVEL == "info" {
			fmt.Printf("Interface: %s, Info: %s\n", iface, info)
		}
		parent := strings.Split(info, ",")[3]
		is_over := strings.Split(info, ",")[2]
		qos_stat := strings.Split(info, ",")[6]
		if is_over == "true" && qos_stat == "0" {
			err := setQosSwitch(config, cookies, parent, iface, 1)
			if err != nil {
				fmt.Println("Error:", err)
			}
		}
	}
}

func changeQosStatus(config Config, QosStatus int) {
	cookies := getCookies(config)
	netWanInterfaces, err := mergeInterfaceFlowAndQosStatus(config, cookies)
	if err != nil {
		// 处理错误，比如打印错误日志
		fmt.Println("查询QoS状态失败:", err)
		// 根据实际情况，可以返回错误或进行其他错误处理
		return
	}
	for iface, info := range netWanInterfaces {
		fmt.Printf("Interface: %s, QosStatus: %s\n", iface, info)
		parent := strings.Split(info, ",")[3]
		setQosSwitch(config, cookies, parent, iface, QosStatus)
		switch QosStatus {
		case 0:
			fmt.Println("QoS is disabled")
		case 1:
			fmt.Println("QoS is enabled")
		default:
			fmt.Printf("Invalid QoS status: %s\n", QosStatus)
		}
	}
}

// dailyTask represents the second job that needs to be done daily
func taskLimitStartAll(config Config) {
	fmt.Println("Daily Task Start All Limit executed at:", time.Now())
	changeQosStatus(config, 1)
}

// dailyTask represents the second job that needs to be done daily
func taskLimitEndAll(config Config) {
	fmt.Println("Daily Task End All Limit executed at:", time.Now())
	changeQosStatus(config, 0)
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

	// Decrypt and validate license
	// License文件名为"license"
	licenseFile := "license"
	// 使用ioutil.ReadFile读取整个文件内容
	content, err := ioutil.ReadFile(licenseFile)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}
	encryptionKey := []byte("K67tJXm88Fq82DkP") // Replace with your actual key
	license, err := DecryptLicense(string(content), encryptionKey)
	if err != nil {
		fmt.Println("Error decrypting license:", err)
		return
	}

	err = ValidateLicense(license)
	if err != nil {
		fmt.Println("License validation failed:", err)
		return
	}

	fmt.Println("License is valid. User:", license.Username)
	fmt.Println("License is valid. ExpriyDate:", license.ExpiryDate)

	taskMain(config)

	// 设置定时任务
	setTimedTasks(config)
}
