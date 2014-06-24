COVERALLS_URL='https://coveralls.io/api/v1/jobs'
sudo LEIN_ROOT=1 lein2 cloverage -o cov --coveralls
curl -F 'json_file=@cov/coveralls.json' "$COVERALLS_URL"

