# REST API Go Applications
This repository contains complete Application Example using our Go REST API wrapper

### Pre-requisites:
Will users need previous registration, account, strategy set-up...? After all, these examples require a pre-existing strategy
Go https://golang.org/dl/

### How to:

**1. Clone this repository to the location of your choice** 

The repository contains the wrapper and all the example listed above together with the classes needed. 

**2. Modify conf.json file with your settings** 

```
"domain" : "http://demo.arthikatrading.com"
"user" : "demo"
"password" : "demo"
```

**3. Modify the following lines in the Go program you would like to run.** 

From here on we will assume it is getPriceStreaming.
```
id1 := wrapper.GetPriceStreamingBegin(secs, nil, wrapper.GRANULARITY_FAB, 5, conf.Interval, processPrices)
```

**4. Run example.**
```javascript
$ go run example.go

...
PriceStreaming:
Security: EUR/USD - TI: Cantor_CNX_1 - Price: 1.11760 - Liquidity: 1000000 - Side: ask
Security: EUR/USD - TI: Cantor_CNX_1 - Price: 1.11770 - Liquidity: 4000000 - Side: ask
Security: EUR/USD - TI: Cantor_CNX_1 - Price: 1.11750 - Liquidity: 5000000 - Side: bid
Security: EUR/USD - TI: Cantor_CNX_1 - Price: 1.11600 - Liquidity: 2000000 - Side: bid
...
```


