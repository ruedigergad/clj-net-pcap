COVERALLS_URL='https://coveralls.io/api/v1/jobs'
sudo LEIN_ROOT=1 lein2 cloverage -o cov --coveralls
sudo chmod 755 cov
sudo chmod 644 cov/coveralls.json
curl -F 'json_file=@cov/coveralls.json' "$COVERALLS_URL"

