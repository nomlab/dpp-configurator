# dpp-configurator
DPP (evice Provisioning Protocol) を用いた Wi-Fi Easy Connect の configurator を実装するために作成したプログラム集

## プログラムリスト
### dpp_auth_request
DPP authentification request パケットを送信するためのプログラム

#### ビルド方法
```bash
gcc dpp_auth_request.c -o dpp_auth_request -lpcap
# or you can use make
make
```

#### 使用方法
```bash
sudo ./dpp_auth_request  
```
