package wrapper

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

const SIDE_BUY string = "buy"
const SIDE_SELL string = "sell"
const SIDE_ASK string = "ask"
const SIDE_BID string = "bid"
const TYPE_MARKET string = "market"
const TYPE_LIMIT string = "limit"
const VALIDITY_DAY string = "day"
const VALIDITY_FILLORKILL string = "fill or kill"
const VALIDITY_INMEDIATEORCANCEL string = "inmediate or cancel"
const VALIDITY_GOODTILLCANCEL string = "good till cancel"
const GRANULARITY_TOB string = "tob"
const GRANULARITY_FAB string = "fab"
const ORDERTYPE_PENDING string = "pending"
const ORDERTYPE_INDETERMINATED string = "indetermined"
const ORDERTYPE_EXECUTED string = "executed"
const ORDERTYPE_CANCELED string = "canceled"
const ORDERTYPE_REJECTED string = "rejected"

const STREAMING_TIMEOUT int = 5

var domain string
var user string
var password string
var url_streaming string
var url_polling string
var url_challenge string
var url_token string
var authentication_port int
var request_port int
var challenge string
var challengeresp string
var token string
var ssl bool
var ssl_cert string
var transport *http.Transport
var insecureSkipVerify bool

type CallBackPriceFunc func(prices []PriceTick)

type CallBackPositionFunc func(position PositionTick)

type CallBackOrderFunc func(position []OrderTick)

type GetAuthorizationChallengeRequest struct {
	GetAuthorizationChallenge ChallengeRequest `json:"getAuthorizationChallenge"`
}

type GetAuthorizationTokenRequest struct {
	GetAuthorizationToken TokenRequest `json:"getAuthorizationToken"`
}

type GetAccountRequest struct {
	GetAccount AccountRequest `json:"getAccount"`
}

type GetInterfaceRequest struct {
	GetInterface InterfaceRequest `json:"getInterface"`
}

type GetPriceRequest struct {
	GetPrice PriceRequest `json:"getPrice"`
}

type GetPositionRequest struct {
	GetPosition PositionRequest `json:"getPosition"`
}

type GetOrderRequest struct {
	GetOrder OrderRequest `json:"getOrder"`
}

type SetOrderRequest struct {
	SetOrder SetOrderRequest2 `json:"setOrder"`
}

type ModifyOrderRequest struct {
	ModifyOrder ModifyOrderRequest2 `json:"modifyOrder"`
}

type CancelOrderRequest struct {
	CancelOrder CancelOrderRequest2 `json:"cancelOrder"`
}

type ChallengeRequest struct {
	User string `json:"user"`
}

type TokenRequest struct {
	User          string `json:"user"`
	Challengeresp string `json:"challengeresp"`
}

type AccountRequest struct {
	User  string `json:"user"`
	Token string `json:"token"`
}

type InterfaceRequest struct {
	User  string `json:"user"`
	Token string `json:"token"`
}

type PriceRequest struct {
	User        string   `json:"user"`
	Token       string   `json:"token"`
	Security    []string `json:"security"`
	Tinterface  []string `json:"tinterface"`
	Granularity string   `json:"granularity"`
	Levels      int      `json:"levels"`
	Interval    int      `json:"interval"`
}

type PositionRequest struct {
	User     string   `json:"user"`
	Token    string   `json:"token"`
	Asset    []string `json:"asset"`
	Security []string `json:"security"`
	Account  []string `json:"account"`
	Interval int      `json:"interval"`
}

type OrderRequest struct {
	User       string   `json:"user"`
	Token      string   `json:"token"`
	Security   []string `json:"security"`
	Tinterface []string `json:"tinterface"`
	Type       []string `json:"type"`
	Interval   int      `json:"interval"`
}

type SetOrderRequest2 struct {
	User  string  `json:"user"`
	Token string  `json:"token"`
	Order []Order `json:"order"`
}

type Order struct {
	Security    string  `json:"security"`
	Tinterface  string  `json:"tinterface"`
	Quantity    int     `json:"quantity"`
	Side        string  `json:"side"`
	Type        string  `json:"type"`
	Timeinforce string  `json:"timeinforce"`
	Price       float64 `json:"price"`
	Expiration  int     `json:"expiration"`
	Userparam   int     `json:"userparam"`
	Tempid      int     `json:"tempid"`
	Result      string  `json:"result"`
}

type ModifyOrderRequest2 struct {
	User  string     `json:"user"`
	Token string     `json:"token"`
	Order []ModOrder `json:"order"`
}

type ModOrder struct {
	Fixid    string  `json:"fixid"`
	Price    float64 `json:"price"`
	Quantity int     `json:"quantity"`
}

type CancelOrderRequest2 struct {
	User  string   `json:"user"`
	Token string   `json:"token"`
	Fixid []string `json:"fixid"`
}

type GetAuthorizationChallengeResponse struct {
	GetAuthorizationChallengeResponse ChallengeResponse `json:"getAuthorizationChallengeResponse"`
}

type GetAuthorizationTokenResponse struct {
	GetAuthorizationTokenResponse TokenResponse `json:"getAuthorizationTokenResponse"`
}

type GetAccountResponse struct {
	GetAccountResponse AccountResponse `json:"getAccountResponse"`
}

type GetInterfaceResponse struct {
	GetInterfaceResponse InterfaceResponse `json:"getInterfaceResponse"`
}

type GetPriceResponse struct {
	GetPriceResponse PriceResponse `json:"getPriceResponse"`
}

type GetPositionResponse struct {
	GetPositionResponse PositionTick `json:"getPositionResponse"`
}

type GetOrderResponse struct {
	GetOrderResponse OrderResponse `json:"getOrderResponse"`
}

type SetOrderResponse struct {
	SetOrderResponse SetOrderResponse2 `json:"setOrderResponse"`
}

type ModifyOrderResponse struct {
	ModifyOrderResponse ModifyOrderResponse2 `json:"modifyOrderResponse"`
}

type CancelOrderResponse struct {
	CancelOrderResponse CancelOrderResponse2 `json:"cancelOrderResponse"`
}

type ChallengeResponse struct {
	Challenge string `json:"challenge"`
	Timestamp string `json:"timestamp"`
}

type TokenResponse struct {
	Token     string `json:"token"`
	Timestamp string `json:"timestamp"`
}

type AccountResponse struct {
	Account   []AccountTick `json:"account"`
	Timestamp string        `json:"timestamp"`
}

type AccountTick struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Style       string `json:"style"`
	Leverage    int    `json:"leverage"`
	Rollover    string `json:"rollover"`
	Settlement  string `json:"settlement"`
}

type InterfaceResponse struct {
	Tinterface []TinterfaceTick `json:"tinterface"`
	Timestamp  string           `json:"timestamp"`
}

type TinterfaceTick struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Account     string `json:"account"`
	Commissions string `json:"commissions"`
}

type PriceResponse struct {
	Tick      []PriceTick `json:"tick"`
	Timestamp string      `json:"timestamp"`
}

type PriceTick struct {
	Security   string  `json:"security"`
	Tinterface string  `json:"tinterface"`
	Price      float64 `json:"price"`
	Pips       int     `json:"pips"`
	Liquidity  int     `json:"liquidity"`
	Side       string  `json:"side"`
}

type PositionTick struct {
	Accounting       AccountingTick         `json:"accounting"`
	AssetPosition    []AssetPositionTick    `json:"assetposition"`
	SecurityPosition []SecurityPositionTick `json:"securityposition"`
	Timestamp        string                 `json:"timestamp"`
}

type AccountingTick struct {
	M2mcurrency string  `json:"m2mcurrency"`
	StrategyPL  float64 `json:"strategyPL"`
	Totalequity float64 `json:"totalequity"`
	Usedmargin  float64 `json:"usedmargin"`
	Freemargin  float64 `json:"freemargin"`
}

type AssetPositionTick struct {
	Account   string  `json:"account"`
	Asset     string  `json:"asset"`
	Exposure  float64 `json:"exposure"`
	Totalrisk float64 `json:"Totalrisk"`
	Pl        float64 `json:"pl"`
}

type SecurityPositionTick struct {
	Account  string  `json:"account"`
	Security string  `json:"security"`
	Exposure float64 `json:"exposure"`
	Side     string  `json:"side"`
	Price    float64 `json:"price"`
	Pips     int     `json:"pips"`
	Pl       float64 `json:"pl"`
}

type OrderResponse struct {
	Order     []OrderTick `json:"order"`
	Timestamp string      `json:"timestamp"`
}

type OrderTick struct {
	Tempid           int     `json:"tempid"`
	Orderid          string  `json:"orderid"`
	Fixid            string  `json:"fixid"`
	Account          string  `json:"account"`
	Tinterface       string  `json:"tinterface"`
	Security         string  `json:"security"`
	Pips             int     `json:"pips"`
	Quantity         int     `json:"quantity"`
	Side             string  `json:"side"`
	Type             string  `json:"type"`
	Limitprice       float64 `json:"limitprice"`
	Maxshowquantity  int     `json:"maxshowquantity"`
	Timeinforce      string  `json:"timeinforce"`
	Seconds          int     `json:"seconds"`
	Milliseconds     int     `json:"milliseconds"`
	Expiration       int     `json:"expiration"`
	Finishedprice    float64 `json:"finishedprice"`
	Finishedquantity int     `json:"finishedquantity"`
	Commcurrrency    string  `json:"commcurrency"`
	Commission       float64 `json:"commission"`
	Priceatstart     float64 `json:"priceatstart"`
	Userparam        int     `json:"userparam"`
	Status           string  `json:"status"`
	Reason           string  `json:"reason"`
}

type SetOrderResponse2 struct {
	Result    int     `json:"result"`
	Message   string  `json:"message"`
	Order     []Order `json:"order"`
	Timestamp string  `json:"timestamp"`
}

type ModifyOrderResponse2 struct {
	Message   string            `json:"message"`
	Order     []ModifyOrderTick `json:"order"`
	Timestamp string            `json:"timestamp"`
}

type CancelOrderResponse2 struct {
	Message   string            `json:"message"`
	Order     []CancelOrderTick `json:"order"`
	Timestamp string            `json:"timestamp"`
}

type ModifyOrderTick struct {
	Fixid  string `json:"fixid"`
	Result string `json:"result"`
}

type CancelOrderTick struct {
	Fixid  string `json:"fixid"`
	Result string `json:"result"`
}

func New(d string, u string, p string, u_streaming string, u_polling string, u_challenge string, u_token string, a_port int, r_port int, is_ssl bool, sslcert string, ver bool) {
	domain = d
	user = u
	password = p
	url_streaming = u_streaming
	url_polling = u_polling
	url_challenge = u_challenge
	url_token = u_token
	authentication_port = a_port
	request_port = r_port
	ssl = is_ssl
	ssl_cert = sslcert
	insecureSkipVerify = ver
}

func DoAuthentication() (err error) {
	if ssl {
		err = getSSlCert()
		if err != nil {
			return
		}
	}
	err = getChallenge()
	if err != nil {
		return
	}
	err = getChallengeResponse()
	if err != nil {
		return
	}
	err = getToken()
	if err != nil {
		return
	}
	return
}

func getSSlCert() (err error) {
	// Load CA cert
	//caCert, err := ioutil.ReadFile("gsalphasha2g2r1.crt")
	client := &http.Client{}
	res, thiserr := client.Get(ssl_cert)
	if thiserr != nil {
		err = thiserr
		return
	}
	caCert, thiserr := ioutil.ReadAll(res.Body)
	if thiserr != nil {
		err = thiserr
		return
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	// Setup HTTPS client
	tlsConfig := &tls.Config{
		RootCAs:            caCertPool,
		InsecureSkipVerify: insecureSkipVerify,
	}
	tlsConfig.BuildNameToCertificate()
	// Patched by Julio
	transport = &http.Transport{TLSClientConfig: tlsConfig}
	return
}

func getChallenge() (err error) {
	url := domain + ":" + strconv.Itoa(authentication_port) + url_challenge
	//fmt.Println("URL:>", url)
	u := ChallengeRequest{
		User: user,
	}
	reqJ := GetAuthorizationChallengeRequest{
		GetAuthorizationChallenge: u,
	}
	bytes, thiserr := polling(reqJ, url)
	if thiserr != nil {
		err = thiserr
		return
	}
	var cresponse GetAuthorizationChallengeResponse
	err = json.Unmarshal(bytes, &cresponse)
	if err != nil {
		return
	}
	challenge = cresponse.GetAuthorizationChallengeResponse.Challenge
	fmt.Println("CHALLENGE: " + challenge)
	return
}

func getChallengeResponse() (err error) {
	a, thiserr := hex.DecodeString(challenge)
	if thiserr != nil {
		err = thiserr
		return
	}
	b := []byte(password)
	c := append(a, b...)
	h := sha1.New()
	h.Write(c)
	bs := h.Sum(nil)
	challengeresp = fmt.Sprintf("%x", bs)
	fmt.Println("CHALLENGERESP: " + challengeresp)
	return
}

func getToken() (err error) {
	url := domain + ":" + strconv.Itoa(authentication_port) + url_token
	//fmt.Println("URL:>", url)
	u := TokenRequest{
		User:          user,
		Challengeresp: challengeresp,
	}
	reqJ := GetAuthorizationTokenRequest{
		GetAuthorizationToken: u,
	}
	bytes, thiserr := polling(reqJ, url)
	if thiserr != nil {
		err = thiserr
		return
	}
	var cresponse GetAuthorizationTokenResponse
	err = json.Unmarshal(bytes, &cresponse)
	if err != nil {
		return
	}
	token = cresponse.GetAuthorizationTokenResponse.Token
	fmt.Println("TOKEN: " + token)
	return
}

func GetAccount() (acs []AccountTick, err error) {
	url := domain + ":" + strconv.Itoa(request_port) + url_polling + "/getAccount"
	//fmt.Println("URL:>", url)
	u := AccountRequest{
		User:  user,
		Token: token,
	}
	reqJ := GetAccountRequest{
		GetAccount: u,
	}
	bytes, thiserr := polling(reqJ, url)
	if thiserr != nil {
		err = thiserr
		return
	}
	var cresponse GetAccountResponse
	err = json.Unmarshal(bytes, &cresponse)
	if err != nil {
		return
	}
	acs = cresponse.GetAccountResponse.Account
	return
}

func GetInterface() (tis []TinterfaceTick, err error) {
	url := domain + ":" + strconv.Itoa(request_port) + url_polling + "/getInterface"
	//fmt.Println("URL:>", url)
	u := InterfaceRequest{
		User:  user,
		Token: token,
	}
	reqJ := GetInterfaceRequest{
		GetInterface: u,
	}
	bytes, thiserr := polling(reqJ, url)
	if thiserr != nil {
		err = thiserr
		return
	}
	var cresponse GetInterfaceResponse
	err = json.Unmarshal(bytes, &cresponse)
	if err != nil {
		return
	}
	tis = cresponse.GetInterfaceResponse.Tinterface
	return
}

func GetPricePolling(secs []string, tis []string, gran string, lev int) (prices []PriceTick, err error) {
	url := domain + ":" + strconv.Itoa(request_port) + url_polling + "/getPrice"
	//fmt.Println("URL:>", url)
	u := PriceRequest{
		User:        user,
		Token:       token,
		Security:    secs,
		Tinterface:  tis,
		Granularity: gran,
		Levels:      lev,
		Interval:    0,
	}
	reqJ := GetPriceRequest{
		GetPrice: u,
	}
	bytes, thiserr := polling(reqJ, url)
	if thiserr != nil {
		err = thiserr
		return
	}
	var cresponse GetPriceResponse
	err = json.Unmarshal(bytes, &cresponse)
	if err != nil {
		return
	}
	prices = cresponse.GetPriceResponse.Tick
	return
}

func GetPositionPolling(asts []string, secs []string, accs []string) (position PositionTick, err error) {
	url := domain + ":" + strconv.Itoa(request_port) + url_polling + "/getPosition"
	//fmt.Println("URL:>", url)
	u := PositionRequest{
		User:     user,
		Token:    token,
		Asset:    asts,
		Security: secs,
		Account:  accs,
		Interval: 0,
	}
	reqJ := GetPositionRequest{
		GetPosition: u,
	}
	bytes, thiserr := polling(reqJ, url)
	if thiserr != nil {
		err = thiserr
		return
	}
	var cresponse GetPositionResponse
	err = json.Unmarshal(bytes, &cresponse)
	if err != nil {
		return
	}
	position = cresponse.GetPositionResponse
	return
}

func GetOrderPolling(secs []string, tis []string, tys []string) (orders []OrderTick, err error) {
	url := domain + ":" + strconv.Itoa(request_port) + url_polling + "/getOrder"
	//fmt.Println("URL:>", url)
	u := OrderRequest{
		User:       user,
		Token:      token,
		Security:   secs,
		Tinterface: tis,
		Type:       tys,
		Interval:   0,
	}
	reqJ := GetOrderRequest{
		GetOrder: u,
	}
	bytes, thiserr := polling(reqJ, url)
	if thiserr != nil {
		err = thiserr
		return
	}
	var cresponse GetOrderResponse
	err = json.Unmarshal(bytes, &cresponse)
	if err != nil {
		return
	}
	orders = cresponse.GetOrderResponse.Order
	return
}

func SetOrder(orders []Order) (ordresp SetOrderResponse2, err error) {
	url := domain + ":" + strconv.Itoa(request_port) + url_polling + "/setOrder"
	//fmt.Println("URL:>", url)
	u := SetOrderRequest2{
		User:  user,
		Token: token,
		Order: orders,
	}
	reqJ := SetOrderRequest{
		SetOrder: u,
	}
	bytes, thiserr := polling(reqJ, url)
	if thiserr != nil {
		err = thiserr
		return
	}
	var cresponse SetOrderResponse
	err = json.Unmarshal(bytes, &cresponse)
	if err != nil {
		return
	}
	ordresp = cresponse.SetOrderResponse
	return
}

func ModifyOrder(modifyorders []ModOrder) (modresp ModifyOrderResponse2, err error) {
	url := domain + ":" + strconv.Itoa(request_port) + url_polling + "/modifyOrder"
	//fmt.Println("URL:>", url)
	u := ModifyOrderRequest2{
		User:  user,
		Token: token,
		Order: modifyorders,
	}
	reqJ := ModifyOrderRequest{
		ModifyOrder: u,
	}
	bytes, thiserr := polling(reqJ, url)
	if thiserr != nil {
		err = thiserr
		return
	}
	var cresponse ModifyOrderResponse
	err = json.Unmarshal(bytes, &cresponse)
	if err != nil {
		return
	}
	modresp = cresponse.ModifyOrderResponse
	return
}

func CancelOrder(cancelorders []string) (canresp CancelOrderResponse2, err error) {
	url := domain + ":" + strconv.Itoa(request_port) + url_polling + "/cancelOrder"
	//fmt.Println("URL:>", url)
	u := CancelOrderRequest2{
		User:  user,
		Token: token,
		Fixid: cancelorders,
	}
	reqJ := CancelOrderRequest{
		CancelOrder: u,
	}
	bytes, thiserr := polling(reqJ, url)
	if thiserr != nil {
		err = thiserr
		return
	}
	var cresponse CancelOrderResponse
	err = json.Unmarshal(bytes, &cresponse)
	if err != nil {
		return
	}
	canresp = cresponse.CancelOrderResponse
	return
}

func GetPriceStreaming(secs []string, tis []string, gran string, lev int, inter int, callback CallBackPriceFunc, quit chan bool) (err error) {
	url := domain + ":" + strconv.Itoa(request_port) + url_streaming + "/getPrice"
	//fmt.Println("URL:>", url)
	u := PriceRequest{
		User:        user,
		Token:       token,
		Security:    secs,
		Tinterface:  tis,
		Granularity: gran,
		Levels:      lev,
		Interval:    inter,
	}
	reqJ := GetPriceRequest{
		GetPrice: u,
	}
	reader, thiserr := streaming(reqJ, url)
	if thiserr != nil {
		err = thiserr
		return
	}
	for {
		select {
		case <-quit:
			fmt.Println("PriceStreaming STOPPED")
			return
		default:
			line, thiserr := readline(reader)
			if thiserr != nil {
				//err = thiserr
				//return err
				continue
			}
			//fmt.Println(string(line))
			bytes := []byte(line)
			var cresponse GetPriceResponse
			err = json.Unmarshal(bytes, &cresponse)
			if err != nil {
				return err
			}
			var prices []PriceTick = cresponse.GetPriceResponse.Tick
			callback(prices)
			//fmt.Println(prices)
		}
	}
}

func GetPriceStreamingBegin(secs []string, tis []string, gran string, lev int, inter int, callback CallBackPriceFunc) (quit chan bool, err error) {
	quit = make(chan bool)
	go func() {
		err = GetPriceStreaming(secs, tis, gran, lev, inter, callback, quit)
	}()
	return
}

func GetPriceStreamingEnd(quit chan bool) {
	quit <- true
}

func GetPositionStreaming(asts []string, secs []string, accs []string, inter int, callback CallBackPositionFunc, quit chan bool) (err error) {
	url := domain + ":" + strconv.Itoa(request_port) + url_streaming + "/getPosition"
	//fmt.Println("URL:>", url)
	u := PositionRequest{
		User:     user,
		Token:    token,
		Asset:    asts,
		Security: secs,
		Account:  accs,
		Interval: inter,
	}
	reqJ := GetPositionRequest{
		GetPosition: u,
	}
	reader, thiserr := streaming(reqJ, url)
	if thiserr != nil {
		err = thiserr
		return
	}
	for {
		select {
		case <-quit:
			fmt.Println("PositionStreaming STOPPED")
			return
		default:
			line, thiserr := readline(reader)
			if thiserr != nil {
				//err = thiserr
				//return err
				continue
			}
			//fmt.Println(string(line))
			bytes := []byte(line)
			var cresponse GetPositionResponse
			err = json.Unmarshal(bytes, &cresponse)
			if err != nil {
				return err
			}
			var position PositionTick = cresponse.GetPositionResponse
			callback(position)
			//fmt.Println(position)
		}
	}
}

func GetPositionStreamingBegin(asts []string, secs []string, accs []string, inter int, callback CallBackPositionFunc) chan bool {
	quit := make(chan bool)
	go GetPositionStreaming(asts, secs, accs, inter, callback, quit)
	return quit
}

func GetPositionStreamingEnd(quit chan bool) {
	quit <- true
}

func GetOrderStreaming(secs []string, tis []string, tys []string, inter int, callback CallBackOrderFunc, quit chan bool) (err error) {
	url := domain + ":" + strconv.Itoa(request_port) + url_streaming + "/getOrder"
	//fmt.Println("URL:>", url)
	u := OrderRequest{
		User:       user,
		Token:      token,
		Security:   secs,
		Tinterface: tis,
		Type:       tys,
		Interval:   inter,
	}
	reqJ := GetOrderRequest{
		GetOrder: u,
	}
	reader, thiserr := streaming(reqJ, url)
	if thiserr != nil {
		err = thiserr
		return
	}
	for {
		select {
		case <-quit:
			fmt.Println("OrderStreaming STOPPED")
			return
		default:
			line, thiserr := readline(reader)
			if thiserr != nil {
				//err = thiserr
				//return err
				continue
			}
			//fmt.Println(string(line))
			bytes := []byte(line)
			var cresponse GetOrderResponse
			err = json.Unmarshal(bytes, &cresponse)
			if err != nil {
				return err
			}
			var orders []OrderTick = cresponse.GetOrderResponse.Order
			callback(orders)
			//fmt.Println(orders)
		}
	}
}

func GetOrderStreamingBegin(secs []string, tis []string, tys []string, inter int, callback CallBackOrderFunc) chan bool {
	quit := make(chan bool)
	go GetOrderStreaming(secs, tis, tys, inter, callback, quit)
	return quit
}

func GetOrderStreamingEnd(quit chan bool) {
	quit <- true
}

func polling(reqJ interface{}, url string) (bytesres []byte, err error) {
	resp, thiserr := doRequest(reqJ, url)
	if thiserr != nil {
		err = thiserr
		return
	}
	defer resp.Body.Close()
	body, thiserr := ioutil.ReadAll(resp.Body)
	if thiserr != nil {
		err = thiserr
		return
	}
	text := string(body)
	//fmt.Println(text)
	bytesres = []byte(text)
	return
}

func streaming(reqJ interface{}, url string) (read *bufio.Reader, err error) {
	resp, thiserr := doRequest(reqJ, url)
	if thiserr != nil {
		err = thiserr
		return
	}
	read = bufio.NewReader(resp.Body)
	return
}

func readline(reader *bufio.Reader) ([]byte, error) {
	var line []byte;
	var thiserr error;
	c1 := make(chan string, 1)
    go func() {
        line, thiserr = reader.ReadBytes('\n')
        c1 <- "finish"
    }()
    select {
    	case <-c1:
        	return line, thiserr
    	case <-time.After(time.Second * time.Duration(STREAMING_TIMEOUT)):
        	return nil, errors.New("TIMEOUT")
    }
}

func doRequest(reqJ interface{}, url string) (resp *http.Response, err error) {
	reqM, thiserr := json.Marshal(reqJ)
	if thiserr != nil {
		err = thiserr
		return
	}
	//fmt.Println(string(reqM))
	req, thiserr := http.NewRequest("POST", url, bytes.NewBuffer(reqM))
	if thiserr != nil {
		err = thiserr
		return
	}
	client := &http.Client{}
	req.Header.Set("Content-Type", "application/json")
	if ssl {
		client = &http.Client{Transport: transport}
	}
	resp, err = client.Do(req)
	return
}
