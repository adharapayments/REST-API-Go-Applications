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

type Wrapper struct {
	domain              string
	user                string
	password            string
	url_streaming       string
	url_polling         string
	url_challenge       string
	url_token           string
	authentication_port int
	request_port        int
	challenge           string
	challengeresp       string
	token               string
	ssl                 bool
	ssl_cert            string
	transport           *http.Transport
	insecureSkipVerify  bool
}

type callBackPriceFunc func(prices []PriceTick)

type callBackPositionFunc func(position PositionTick)

type callBackOrderFunc func(position []OrderTick)

type getAuthorizationChallengeRequest struct {
	GetAuthorizationChallenge challengeRequest `json:"getAuthorizationChallenge"`
}

type getAuthorizationTokenRequest struct {
	GetAuthorizationToken tokenRequest `json:"getAuthorizationToken"`
}

type getAccountRequest struct {
	GetAccount accountRequest `json:"getAccount"`
}

type getInterfaceRequest struct {
	GetInterface interfaceRequest `json:"getInterface"`
}

type getPriceRequest struct {
	GetPrice priceRequest `json:"getPrice"`
}

type getPositionRequest struct {
	GetPosition positionRequest `json:"getPosition"`
}

type getOrderRequest struct {
	GetOrder orderRequest `json:"getOrder"`
}

type setOrderRequest struct {
	SetOrder setOrderRequest2 `json:"setOrder"`
}

type modifyOrderRequest struct {
	ModifyOrder modifyOrderRequest2 `json:"modifyOrder"`
}

type cancelOrderRequest struct {
	CancelOrder cancelOrderRequest2 `json:"cancelOrder"`
}

type challengeRequest struct {
	User string `json:"user"`
}

type tokenRequest struct {
	User          string `json:"user"`
	Challengeresp string `json:"challengeresp"`
}

type accountRequest struct {
	User  string `json:"user"`
	Token string `json:"token"`
}

type interfaceRequest struct {
	User  string `json:"user"`
	Token string `json:"token"`
}

type priceRequest struct {
	User        string   `json:"user"`
	Token       string   `json:"token"`
	Security    []string `json:"security"`
	Tinterface  []string `json:"tinterface"`
	Granularity string   `json:"granularity"`
	Levels      int      `json:"levels"`
	Interval    int      `json:"interval"`
}

type positionRequest struct {
	User     string   `json:"user"`
	Token    string   `json:"token"`
	Asset    []string `json:"asset"`
	Security []string `json:"security"`
	Account  []string `json:"account"`
	Interval int      `json:"interval"`
}

type orderRequest struct {
	User       string   `json:"user"`
	Token      string   `json:"token"`
	Security   []string `json:"security"`
	Tinterface []string `json:"tinterface"`
	Type       []string `json:"type"`
	Interval   int      `json:"interval"`
}

type setOrderRequest2 struct {
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

type modifyOrderRequest2 struct {
	User  string     `json:"user"`
	Token string     `json:"token"`
	Order []ModOrder `json:"order"`
}

type ModOrder struct {
	Fixid    string  `json:"fixid"`
	Price    float64 `json:"price"`
	Quantity int     `json:"quantity"`
}

type cancelOrderRequest2 struct {
	User  string   `json:"user"`
	Token string   `json:"token"`
	Fixid []string `json:"fixid"`
}

type getAuthorizationChallengeResponse struct {
	GetAuthorizationChallengeResponse challengeResponse `json:"getAuthorizationChallengeResponse"`
}

type getAuthorizationTokenResponse struct {
	GetAuthorizationTokenResponse tokenResponse `json:"getAuthorizationTokenResponse"`
}

type getAccountResponse struct {
	GetAccountResponse accountResponse `json:"getAccountResponse"`
}

type getInterfaceResponse struct {
	GetInterfaceResponse interfaceResponse `json:"getInterfaceResponse"`
}

type getPriceResponse struct {
	GetPriceResponse priceResponse `json:"getPriceResponse"`
}

type getPositionResponse struct {
	GetPositionResponse PositionTick `json:"getPositionResponse"`
}

type getOrderResponse struct {
	GetOrderResponse orderResponse `json:"getOrderResponse"`
}

type setOrderResponse struct {
	SetOrderResponse SetOrderResponse2 `json:"setOrderResponse"`
}

type modifyOrderResponse struct {
	ModifyOrderResponse ModifyOrderResponse2 `json:"modifyOrderResponse"`
}

type cancelOrderResponse struct {
	CancelOrderResponse CancelOrderResponse2 `json:"cancelOrderResponse"`
}

type challengeResponse struct {
	Challenge string `json:"challenge"`
	Timestamp string `json:"timestamp"`
}

type tokenResponse struct {
	Token     string `json:"token"`
	Timestamp string `json:"timestamp"`
}

type accountResponse struct {
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

type interfaceResponse struct {
	Tinterface []TinterfaceTick `json:"tinterface"`
	Timestamp  string           `json:"timestamp"`
}

type TinterfaceTick struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Account     string `json:"account"`
	Commissions string `json:"commissions"`
}

type priceResponse struct {
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

type orderResponse struct {
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

func CreateWrapper(d string, u string, p string, u_streaming string, u_polling string, u_challenge string, u_token string, a_port int, r_port int, is_ssl bool, sslcert string, ver bool) (*Wrapper){
	wrapper := &Wrapper{
		domain              : d,
		user                : u,
		password            : p,
		url_streaming       : u_streaming,
		url_polling         : u_polling,
		url_challenge       : u_challenge,
		url_token           : u_token,
		authentication_port : a_port,
		request_port        : r_port,
		ssl                 : is_ssl,
		ssl_cert            : sslcert,
		insecureSkipVerify  : ver,
	}
	return wrapper
}

func (w *Wrapper) DoAuthentication() (err error) {
	if ssl {
		err = w.getSSlCert()
		if err != nil {
			return
		}
	}
	err = w.getChallenge()
	if err != nil {
		return
	}
	err = w.getChallengeResponse()
	if err != nil {
		return
	}
	err = w.getToken()
	if err != nil {
		return
	}
	return
}

func (w *Wrapper) getSSlCert() (err error) {
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
	w.transport = &http.Transport{TLSClientConfig: tlsConfig}
	return
}

func (w *Wrapper) getChallenge() (err error) {
	url := w.domain + ":" + strconv.Itoa(w.authentication_port) + w.url_challenge
	//fmt.Println("URL:>", url)
	u := challengeRequest{
		User: w.user,
	}
	reqJ := getAuthorizationChallengeRequest{
		GetAuthorizationChallenge: u,
	}
	bytes, thiserr := polling(reqJ, url)
	if thiserr != nil {
		err = thiserr
		return
	}
	var cresponse getAuthorizationChallengeResponse
	err = json.Unmarshal(bytes, &cresponse)
	if err != nil {
		return
	}
	w.challenge = cresponse.GetAuthorizationChallengeResponse.Challenge
	//fmt.Println("CHALLENGE: " + w.challenge)
	return
}

func (w *Wrapper) getChallengeResponse() (err error) {
	a, thiserr := hex.DecodeString(w.challenge)
	if thiserr != nil {
		err = thiserr
		return
	}
	b := []byte(w.password)
	c := append(a, b...)
	h := sha1.New()
	h.Write(c)
	bs := h.Sum(nil)
	w.challengeresp = fmt.Sprintf("%x", bs)
	//fmt.Println("CHALLENGERESP: " + w.challengeresp)
	return
}

func (w *Wrapper) getToken() (err error) {
	url := w.domain + ":" + strconv.Itoa(w.authentication_port) + w.url_token
	//fmt.Println("URL:>", url)
	u := tokenRequest{
		User:          w.user,
		Challengeresp: w.challengeresp,
	}
	reqJ := getAuthorizationTokenRequest{
		GetAuthorizationToken: u,
	}
	bytes, thiserr := polling(reqJ, url)
	if thiserr != nil {
		err = thiserr
		return
	}
	var cresponse getAuthorizationTokenResponse
	err = json.Unmarshal(bytes, &cresponse)
	if err != nil {
		return
	}
	w.token = cresponse.GetAuthorizationTokenResponse.Token
	fmt.Println("TOKEN: " + w.token)
	return
}

func (w *Wrapper) GetAccount() (acs []AccountTick, err error) {
	url := w.domain + ":" + strconv.Itoa(w.request_port) + w.url_polling + "/getAccount"
	//fmt.Println("URL:>", url)
	u := accountRequest{
		User:  w.user,
		Token: w.token,
	}
	reqJ := getAccountRequest{
		GetAccount: u,
	}
	bytes, thiserr := polling(reqJ, url)
	if thiserr != nil {
		err = thiserr
		return
	}
	var cresponse getAccountResponse
	err = json.Unmarshal(bytes, &cresponse)
	if err != nil {
		return
	}
	acs = cresponse.GetAccountResponse.Account
	return
}

func (w *Wrapper) GetInterface() (tis []TinterfaceTick, err error) {
	url := w.domain + ":" + strconv.Itoa(w.request_port) + w.url_polling + "/getInterface"
	//fmt.Println("URL:>", url)
	u := interfaceRequest{
		User:  w.user,
		Token: w.token,
	}
	reqJ := getInterfaceRequest{
		GetInterface: u,
	}
	bytes, thiserr := polling(reqJ, url)
	if thiserr != nil {
		err = thiserr
		return
	}
	var cresponse getInterfaceResponse
	err = json.Unmarshal(bytes, &cresponse)
	if err != nil {
		return
	}
	tis = cresponse.GetInterfaceResponse.Tinterface
	return
}

func (w *Wrapper) GetPricePolling(secs []string, tis []string, gran string, lev int) (prices []PriceTick, err error) {
	url := w.domain + ":" + strconv.Itoa(w.request_port) + w.url_polling + "/getPrice"
	//fmt.Println("URL:>", url)
	u := priceRequest{
		User:        w.user,
		Token:       w.token,
		Security:    secs,
		Tinterface:  tis,
		Granularity: gran,
		Levels:      lev,
		Interval:    0,
	}
	reqJ := getPriceRequest{
		GetPrice: u,
	}
	bytes, thiserr := polling(reqJ, url)
	if thiserr != nil {
		err = thiserr
		return
	}
	var cresponse getPriceResponse
	err = json.Unmarshal(bytes, &cresponse)
	if err != nil {
		return
	}
	prices = cresponse.GetPriceResponse.Tick
	return
}

func (w *Wrapper) GetPositionPolling(asts []string, secs []string, accs []string) (position PositionTick, err error) {
	url := w.domain + ":" + strconv.Itoa(w.request_port) + w.url_polling + "/getPosition"
	//fmt.Println("URL:>", url)
	u := positionRequest{
		User:     w.user,
		Token:    w.token,
		Asset:    asts,
		Security: secs,
		Account:  accs,
		Interval: 0,
	}
	reqJ := getPositionRequest{
		GetPosition: u,
	}
	bytes, thiserr := polling(reqJ, url)
	if thiserr != nil {
		fmt.Println("GetPositionPolling u:>", u)
		fmt.Println(thiserr)
		err = thiserr
		return
	}
	var cresponse getPositionResponse
	err = json.Unmarshal(bytes, &cresponse)
	if err != nil {
		fmt.Println("GetPositionPolling u2:>", u)
		fmt.Println("GetPositionPolling response:>", bytes)
		fmt.Println(err)
		return
	}
	position = cresponse.GetPositionResponse
	return
}

func (w *Wrapper) GetOrderPolling(secs []string, tis []string, tys []string) (orders []OrderTick, err error) {
	url := w.domain + ":" + strconv.Itoa(w.request_port) + w.url_polling + "/getOrder"
	//fmt.Println("URL:>", url)
	u := orderRequest{
		User:       w.user,
		Token:      w.token,
		Security:   secs,
		Tinterface: tis,
		Type:       tys,
		Interval:   0,
	}
	reqJ := getOrderRequest{
		GetOrder: u,
	}
	bytes, thiserr := polling(reqJ, url)
	if thiserr != nil {
		err = thiserr
		return
	}
	var cresponse getOrderResponse
	err = json.Unmarshal(bytes, &cresponse)
	if err != nil {
		return
	}
	orders = cresponse.GetOrderResponse.Order
	return
}

func (w *Wrapper) SetOrder(orders []Order) (ordresp SetOrderResponse2, err error) {
	url := w.domain + ":" + strconv.Itoa(w.request_port) + w.url_polling + "/setOrder"
	//fmt.Println("URL:>", url)
	u := setOrderRequest2{
		User:  w.user,
		Token: w.token,
		Order: orders,
	}
	reqJ := setOrderRequest{
		SetOrder: u,
	}
	bytes, thiserr := polling(reqJ, url)
	if thiserr != nil {
		err = thiserr
		return
	}
	var cresponse setOrderResponse
	err = json.Unmarshal(bytes, &cresponse)
	if err != nil {
		return
	}
	ordresp = cresponse.SetOrderResponse
	return
}

func (w *Wrapper) ModifyOrder(modifyorders []ModOrder) (modresp ModifyOrderResponse2, err error) {
	url := w.domain + ":" + strconv.Itoa(w.request_port) + w.url_polling + "/modifyOrder"
	//fmt.Println("URL:>", url)
	u := modifyOrderRequest2{
		User:  w.user,
		Token: w.token,
		Order: modifyorders,
	}
	reqJ := modifyOrderRequest{
		ModifyOrder: u,
	}
	bytes, thiserr := polling(reqJ, url)
	if thiserr != nil {
		err = thiserr
		return
	}
	var cresponse modifyOrderResponse
	err = json.Unmarshal(bytes, &cresponse)
	if err != nil {
		return
	}
	modresp = cresponse.ModifyOrderResponse
	return
}

func (w *Wrapper) CancelOrder(cancelorders []string) (canresp CancelOrderResponse2, err error) {
	url := w.domain + ":" + strconv.Itoa(w.request_port) + w.url_polling + "/cancelOrder"
	//fmt.Println("URL:>", url)
	u := cancelOrderRequest2{
		User:  w.user,
		Token: w.token,
		Fixid: cancelorders,
	}
	reqJ := cancelOrderRequest{
		CancelOrder: u,
	}
	bytes, thiserr := polling(reqJ, url)
	if thiserr != nil {
		err = thiserr
		return
	}
	var cresponse cancelOrderResponse
	err = json.Unmarshal(bytes, &cresponse)
	if err != nil {
		return
	}
	canresp = cresponse.CancelOrderResponse
	return
}

func (w *Wrapper) GetPriceStreaming(secs []string, tis []string, gran string, lev int, inter int, callback callBackPriceFunc, quit chan bool) (err error) {
	url := w.domain + ":" + strconv.Itoa(w.request_port) + w.url_streaming + "/getPrice"
	//fmt.Println("URL:>", url)
	u := priceRequest{
		User:        w.user,
		Token:       w.token,
		Security:    secs,
		Tinterface:  tis,
		Granularity: gran,
		Levels:      lev,
		Interval:    inter,
	}
	reqJ := getPriceRequest{
		GetPrice: u,
	}
	//fmt.Println(token)
	//fmt.Println(u)
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
			var cresponse getPriceResponse
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

func (w *Wrapper) GetPriceStreamingBegin(secs []string, tis []string, gran string, lev int, inter int, callback callBackPriceFunc) (quit chan bool, err error) {
	quit = make(chan bool)
	go func() {
		err = w.GetPriceStreaming(secs, tis, gran, lev, inter, callback, quit)
	}()
	return
}

func (w *Wrapper) GetPriceStreamingEnd(quit chan bool) {
	quit <- true
}

func (w *Wrapper) GetPositionStreaming(asts []string, secs []string, accs []string, inter int, callback callBackPositionFunc, quit chan bool) (err error) {
	url := w.domain + ":" + strconv.Itoa(w.request_port) + w.url_streaming + "/getPosition"
	//fmt.Println("URL:>", url)
	u := positionRequest{
		User:     w.user,
		Token:    w.token,
		Asset:    asts,
		Security: secs,
		Account:  accs,
		Interval: inter,
	}
	reqJ := getPositionRequest{
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
			var cresponse getPositionResponse
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

func (w *Wrapper) GetPositionStreamingBegin(asts []string, secs []string, accs []string, inter int, callback callBackPositionFunc) chan bool {
	quit := make(chan bool)
	go w.GetPositionStreaming(asts, secs, accs, inter, callback, quit)
	return quit
}

func (w *Wrapper) GetPositionStreamingEnd(quit chan bool) {
	quit <- true
}

func (w *Wrapper) GetOrderStreaming(secs []string, tis []string, tys []string, inter int, callback callBackOrderFunc, quit chan bool) (err error) {
	url := w.domain + ":" + strconv.Itoa(w.request_port) + w.url_streaming + "/getOrder"
	//fmt.Println("URL:>", url)
	u := orderRequest{
		User:       w.user,
		Token:      w.token,
		Security:   secs,
		Tinterface: tis,
		Type:       tys,
		Interval:   inter,
	}
	reqJ := getOrderRequest{
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
			var cresponse getOrderResponse
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

func (w *Wrapper) GetOrderStreamingBegin(secs []string, tis []string, tys []string, inter int, callback callBackOrderFunc) chan bool {
	quit := make(chan bool)
	go w.GetOrderStreaming(secs, tis, tys, inter, callback, quit)
	return quit
}

func (w *Wrapper) GetOrderStreamingEnd(quit chan bool) {
	quit <- true
}

func polling(reqJ interface{}, url string) (bytesres []byte, err error) {
	resp, thiserr := doRequest(reqJ, url)
	if thiserr != nil {
		fmt.Println("polling req: ")
		fmt.Println(reqJ)
		fmt.Println(thiserr)
		err = thiserr
		return
	}
	defer resp.Body.Close()
	body, thiserr := ioutil.ReadAll(resp.Body)
	if thiserr != nil {
		fmt.Println("polling resp: ")
		fmt.Println(resp)
		fmt.Println(resp.Body)
		fmt.Println(thiserr)
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

func (w *Wrapper) ChangeToken() () {
	w.token="WRONG"
}