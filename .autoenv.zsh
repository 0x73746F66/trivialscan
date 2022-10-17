echo -e "\033[1;36m
▀▀█▀▀ █▀▀█ ░▀░ ▀█░█▀ ░▀░ █▀▀█ █░░ █▀▀ █▀▀ █▀▀█ █▀▀▄
░░█░░ █▄▄▀ ▀█▀ ░█▄█░ ▀█▀ █▄▄█ █░░ ▀▀█ █░░ █▄▄█ █░░█
░░▀░░ ▀░▀▀ ▀▀▀ ░░▀░░ ▀▀▀ ▀░░▀ ▀▀▀ ▀▀▀ ▀▀▀ ▀░░▀ ▀░░▀\033[0m"

if [[ -f .env ]]; then
  source .env
fi
if [[ -f .env.local ]]; then
  source .env.local
fi
readonly default_env=Dev
export APP_ENV=${APP_ENV:-${default_env}}
readonly stored_api_url=$(aws ssm get-parameter --name "/${APP_ENV}/Deploy/trivialscan-lambda/trivialscan_lambda_url" --output text --with-decryption --query 'Parameter.Value' 2>/dev/null)
export API_URL=${API_URL:-${stored_api_url}}
aws sts get-caller-identity
[ -z "${APP_ENV}" ] && echo -e "${RED}APP_ENV not set${NC}"
[ -z "${API_URL}" ] && echo -e "${RED}API_URL not set${NC}"
[ -z "${RUNNER_TOKEN}" ] && echo -e "${RED}RUNNER_TOKEN not set${NC}"
git fetch
git status
echo -e "\033[1;36m$(make --version)\033[0m\n$(make help)"
[ -f .venv3.9/bin/activate ] && source .venv3.9/bin/activate
