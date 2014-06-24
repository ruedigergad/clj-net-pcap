COVERALLS_URL='https://coveralls.io/api/v1/jobs'
TRAVIS_JOB_ID_TMP=$TRAVIS_JOB_ID
echo "Job id: $TRAVIS_JOB_ID_TMP"
sudo LEIN_ROOT=1 TRAVIS=true TRAVIS_JOB_ID=$TRAVIS_JOB_ID_TMP lein2 cloverage -o cov --coveralls
sudo chmod 755 cov
sudo chmod 644 cov/coveralls.json
curl -F 'json_file=@cov/coveralls.json' "$COVERALLS_URL"

