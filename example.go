package main

import (
	"encoding/json"
	"fmt"
	"github.com/Arthika/REST-API-Go-Applications/wrapper"
	"strconv"
	"time"
	"os"
	"log"
)

type Configuration struct {
	Is_ssl                  bool
	Domain                  string
	User                    string
	Password                string
	Url_streaming           string
	Url_polling             string
	Url_challenge           string
	Url_token               string
	Authentication_port     int
	Request_port            int
	Interval                int
	Ssl_domain              string
	Ssl_authentication_port int
	Ssl_request_port        int
	Ssl_cert                string
	Insecure_skip_verify    bool
}

func main() {

	// Settings
	var id1 chan bool
	var id2 chan bool
	file, _ := os.Open("conf.json")
	decoder := json.NewDecoder(file)
	conf := Configuration{}
	err := decoder.Decode(&conf)
	if err != nil {
		fmt.Println("error:", err)
	}
	fmt.Println(conf)

	// wrapper authentication


	if conf.Is_ssl {
		wrapper.New(conf.Ssl_domain, conf.User, conf.Password, conf.Url_streaming, conf.Url_polling, conf.Url_challenge, conf.Url_token, conf.Ssl_authentication_port, conf.Ssl_request_port, conf.Is_ssl, conf.Ssl_cert, conf.Insecure_skip_verify)
	} else {
		wrapper.New(conf.Domain, conf.User, conf.Password, conf.Url_streaming, conf.Url_polling, conf.Url_challenge, conf.Url_token, conf.Authentication_port, conf.Request_port, conf.Is_ssl, conf.Ssl_cert, conf.Insecure_skip_verify)
	}
	err = wrapper.DoAuthentication()
	if err != nil {
		log.Fatal("Error in wrapper authentication:", err)
	}

	// get accounts
	accs, err := wrapper.GetAccount()
	if err != nil {
		log.Fatal("Error getting accounts:", err)
	}
	fmt.Println("Accounts:") 
	for i := 0; i < len(accs); i++ {
		var acc wrapper.AccountTick = accs[i]
		fmt.Println("Account - Name: " + acc.Name + " - Description: " + acc.Description + " - Style: " + acc.Style + " - Leverage: " + strconv.Itoa(acc.Leverage) + " - RollOver: " + acc.Rollover + " - Settlement: " + acc.Settlement)
	}

	// get tinterfaces
	tis, err := wrapper.GetInterface()
	if err != nil {
		log.Fatal("Error getting interfaces:", err)
	}
	fmt.Println("Tinterfaces:")
	for i := 0; i < len(tis); i++ {
		var ti wrapper.TinterfaceTick = tis[i]
		fmt.Println("Name: " + ti.Name + " - Description: " + ti.Description + " - Account: " + ti.Account + " - Commissions: " + ti.Commissions)
	}
	var ti string = tis[0].Name
	var sec string = "EUR/USD"

	secs := []string{sec}
	secs2 := []string{"GBP/USD", "USD/JPY"}

	// get prices (Polling)
	var bidprice float64
	prices, err := wrapper.GetPricePolling(secs, nil, wrapper.GRANULARITY_FAB, 5)
	if err != nil {
		log.Fatal("Error getting prices:", err)
	}
	fmt.Println("PricePolling:")
	for i := 0; i < len(prices); i++ {
		var price wrapper.PriceTick = prices[i]
		fmt.Println("Security: " + price.Security + " - TI: " + price.Tinterface + " - Price: " + strconv.FormatFloat(price.Price, 'f', price.Pips, 64) + " - Liquidity: " + strconv.Itoa(price.Liquidity) + " - Side: " + price.Side)
		if (price.Side == wrapper.SIDE_ASK && price.Tinterface == tis[0].Name){
			bidprice = price.Price
			//fmt.Println(bidprice)
		}
	}

	// function to process prices from streaming
	processPrices := func(prices []wrapper.PriceTick)() {
		fmt.Println("PriceStreaming:")
		for i := 0; i < len(prices); i++ {
			var price wrapper.PriceTick = prices[i]
			fmt.Println("Security: " + price.Security + " - TI: " + price.Tinterface + " - Price: " + strconv.FormatFloat(price.Price, 'f', price.Pips, 64) + " - Liquidity: " + strconv.Itoa(price.Liquidity) + " - Side: " + price.Side)
		}
	}

	// open first price streaming
	id1, err = wrapper.GetPriceStreamingBegin(secs, nil, wrapper.GRANULARITY_FAB, 5, conf.Interval, processPrices)

	time.Sleep(2000 * time.Millisecond)

	// open second price streaming
	id2, err = wrapper.GetPriceStreamingBegin(secs2, nil, wrapper.GRANULARITY_TOB, 1, conf.Interval, processPrices)

	time.Sleep(2000 * time.Millisecond)

	// close second price streaming
	wrapper.GetPriceStreamingEnd(id2)

	time.Sleep(2000 * time.Millisecond)

	// close first price streaming
	wrapper.GetPriceStreamingEnd(id1)


	// get positions (Polling)
	position, err := wrapper.GetPositionPolling(nil, nil, nil)
	if err != nil {
		log.Fatal("Error getting positions:", err)
	}
	fmt.Println("PositionPolling:")
	var accounting wrapper.AccountingTick = position.Accounting
	fmt.Println("PL: " + strconv.FormatFloat(accounting.StrategyPL, 'f', 6, 64) + " - TotalEquity: " + strconv.FormatFloat(accounting.Totalequity, 'f', 6, 64) + " - UsedMargin: " + strconv.FormatFloat(accounting.Usedmargin, 'f', 6, 64) + " - FreeMargin: " + strconv.FormatFloat(accounting.Freemargin, 'f', 6, 64));
	var assetpositions []wrapper.AssetPositionTick = position.AssetPosition
	for i := 0; i < len(assetpositions); i++ {
		var assetposition wrapper.AssetPositionTick = assetpositions[i]
		fmt.Println("Asset: " + assetposition.Asset + " - Account: " + assetposition.Account + " - Exposure: " + strconv.FormatFloat(assetposition.Exposure, 'f', 6, 64) + " - TotalRisk: " + strconv.FormatFloat(assetposition.Totalrisk, 'f', 6, 64));
	}
	var securitypositions []wrapper.SecurityPositionTick = position.SecurityPosition
	for i := 0; i < len(securitypositions); i++ {
		var securityposition wrapper.SecurityPositionTick = securitypositions[i]
		fmt.Println("Security: " + securityposition.Security + " - Account: " + securityposition.Account + " - Side: " + securityposition.Side + " - Exposure: " + strconv.FormatFloat(securityposition.Exposure, 'f', 6, 64) + " - Price: " + strconv.FormatFloat(securityposition.Price, 'f', securityposition.Pips, 64));
	}

	// function to process position from streaming
	processPosition := func(position wrapper.PositionTick)() {
		fmt.Println("PositionStreaming:")
		var accounting wrapper.AccountingTick = position.Accounting
		fmt.Println("PL: " + strconv.FormatFloat(accounting.StrategyPL, 'f', 6, 64) + " - TotalEquity: " + strconv.FormatFloat(accounting.Totalequity, 'f', 6, 64) + " - UsedMargin: " + strconv.FormatFloat(accounting.Usedmargin, 'f', 6, 64) + " - FreeMargin: " + strconv.FormatFloat(accounting.Freemargin, 'f', 6, 64));
		var assetpositions []wrapper.AssetPositionTick = position.AssetPosition
		for i := 0; i < len(assetpositions); i++ {
			var assetposition wrapper.AssetPositionTick = assetpositions[i]
			fmt.Println("Asset: " + assetposition.Asset + " - Account: " + assetposition.Account + " - Exposure: " + strconv.FormatFloat(assetposition.Exposure, 'f', 6, 64) + " - TotalRisk: " + strconv.FormatFloat(assetposition.Totalrisk, 'f', 6, 64));
		}
		var securitypositions []wrapper.SecurityPositionTick = position.SecurityPosition
		for i := 0; i < len(securitypositions); i++ {
			var securityposition wrapper.SecurityPositionTick = securitypositions[i]
			fmt.Println("Security: " + securityposition.Security + " - Account: " + securityposition.Account + " - Side: " + securityposition.Side + " - Exposure: " + strconv.FormatFloat(securityposition.Exposure, 'f', 6, 64) + " - Price: " + strconv.FormatFloat(securityposition.Price, 'f', securityposition.Pips, 64));
		}
	}

	// open position streaming
	idPos1 := wrapper.GetPositionStreamingBegin(nil, nil, nil, conf.Interval, processPosition)

	time.Sleep(2000 * time.Millisecond)

	// close position streaming
	wrapper.GetPositionStreamingEnd(idPos1)

	// get orders (Polling)
	orders, err := wrapper.GetOrderPolling(nil, nil, nil)
	if err != nil {
		log.Fatal("Error getting orders:", err)
	}
	fmt.Println("OrderPolling:")
	for i := 0; i < len(orders); i++ {
		var order wrapper.OrderTick = orders[i]
		fmt.Println("TempId: " + strconv.Itoa(order.Tempid) + " - OrderId: " + order.Orderid + " - Security: " + order.Security + " - Tinterface: " + order.Tinterface + " - Quantity: " + strconv.Itoa(order.Quantity) + " - Type: " + order.Type + " - Side: " + order.Side + " - Status: " + order.Status + " - Price: " + strconv.FormatFloat(order.Limitprice, 'f', order.Pips, 64));
	}

	// function to process orders from streaming
	processOrders := func(orders []wrapper.OrderTick)() {
		fmt.Println("OrderStreaming: " + strconv.Itoa(len(orders)) + " orders")
		for i := 0; i < len(orders); i++ {
			var order wrapper.OrderTick = orders[i]
			fmt.Println("TempId: " + strconv.Itoa(order.Tempid) + " - OrderId: " + order.Orderid + " - Security: " + order.Security + " - Tinterface: " + order.Tinterface + " - Quantity: " + strconv.Itoa(order.Quantity) + " - Type: " + order.Type + " - Side: " + order.Side + " - Status: " + order.Status + " - Price: " + strconv.FormatFloat(order.Limitprice, 'f', order.Pips, 64));
		}
	}

	// open order streaming
	idOrder1 := wrapper.GetOrderStreamingBegin(nil, nil, nil, conf.Interval, processOrders)

	time.Sleep(2000 * time.Millisecond)

	// create two orders (the orders appear in order streaming)
	var order1 wrapper.Order = wrapper.Order{}
	order1.Security = sec
	order1.Tinterface = ti
	order1.Quantity = 500000
	order1.Side = wrapper.SIDE_BUY
	order1.Type = wrapper.TYPE_LIMIT
	order1.Timeinforce = wrapper.VALIDITY_DAY
	order1.Price = bidprice - 0.0010
	fmt.Println(order1)
	var order2 wrapper.Order = wrapper.Order{}
	order2.Security = sec
	order2.Tinterface = ti
	order2.Quantity = 1000000
	order2.Side = wrapper.SIDE_SELL
	order2.Type = wrapper.TYPE_MARKET
	order2.Timeinforce = wrapper.VALIDITY_FILLORKILL
	var setorders []wrapper.Order = []wrapper.Order{order1, order2}
	//fmt.Println(setorders)
	setorderresponse, err := wrapper.SetOrder(setorders)
	if err != nil {
		log.Fatal("Error setting orders:", err)
	}
	fmt.Println("Result: " + strconv.Itoa(setorderresponse.Result) + " - Message: " + setorderresponse.Message)
	for i := 0; i < len(setorderresponse.Order); i++ {
		var order wrapper.Order = setorderresponse.Order[i]
		fmt.Println("TempId: " + strconv.Itoa(order.Tempid) + " - Result: " + order.Result);
	}

	time.Sleep(2000 * time.Millisecond)

	// get pending orders (Polling), modify the first one and then cancel it (changes appear in order streaming)
	pendingorders, err := wrapper.GetOrderPolling([]string{sec}, []string{ti}, []string{wrapper.ORDERTYPE_PENDING})
	if err != nil {
		log.Fatal("Error getting pending orders:", err)
	}
	if (len(pendingorders)>0){

		// getting first pending order
		var pendingorder wrapper.OrderTick = pendingorders[0]

		// modify pending order
		var modifyorder1 wrapper.ModOrder = wrapper.ModOrder{}
		modifyorder1.Fixid = pendingorder.Fixid
		modifyorder1.Price = pendingorder.Limitprice
		modifyorder1.Quantity = pendingorder.Quantity * 2
		var modifyorders []wrapper.ModOrder = []wrapper.ModOrder{modifyorder1}
		modifyorderresponse, err := wrapper.ModifyOrder(modifyorders)
		if err != nil {
			log.Fatal("Error modifying orders:", err)
		}
		fmt.Println("Message: " + modifyorderresponse.Message)
		for i := 0; i < len(modifyorderresponse.Order); i++ {
			var modifyordertick wrapper.ModifyOrderTick = modifyorderresponse.Order[i]
			fmt.Println("FixId: " + modifyordertick.Fixid + " - Result: " + modifyordertick.Result);
		}

		time.Sleep(2000 * time.Millisecond)

		// cancel order
		var cancelorders []string = []string{pendingorder.Fixid}
		cancelorderresponse, err := wrapper.CancelOrder(cancelorders)
		if err != nil {
			log.Fatal("Error canceling orders:", err)
		}
		fmt.Println("Message: " + cancelorderresponse.Message)
		for i := 0; i < len(cancelorderresponse.Order); i++ {
			var cancelordertick wrapper.CancelOrderTick = cancelorderresponse.Order[i]
			fmt.Println("FixId: " + cancelordertick.Fixid + " - Result: " + cancelordertick.Result);
		}
	}

	time.Sleep(2000 * time.Millisecond)

	// close order streaming
	wrapper.GetPriceStreamingEnd(idOrder1)


	fmt.Println("**********END**********")

}
