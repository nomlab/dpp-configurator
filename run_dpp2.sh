#!/bin/zsh

# 1つ目のコマンドをバックグラウンドで実行
sudo ./dpp-configurator wlo1 MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgACCcWFqRtN+f0loEUgGIXDnMXPrjl92u2pV97Ff6DjUD8= 34:85:18:82:4A:28 12:22:33:44:55:66 &


# 2つ目のコマンドをバックグラウンドで実行
sudo ./dpp-configurator wlo1 MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgACUxij47rgmGQVIP3aMmyHZJ/DaxlyF+2li5tOofYswnE= 48:27:e2:84:59:18 52:23:33:44:55:55 &

# 全てのバックグラウンドプロセスが終了するのを待つ
wait

echo "両方のプロセスが終了しました。"
