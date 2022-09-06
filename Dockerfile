FROM docker.io/gitlab/gitlab-runner

ENV RUNNER_TOKEN=${RUNNER_TOKEN}
ENV DEBIAN_FRONTEND=noninteractive
ENV CFLAGS="-O0"
ENV STATICBUILD=true

COPY requirements-ci.txt .
RUN apt-get update -q \
    && apt-get install -qy --no-install-recommends \
        acl \
        build-essential \
        ca-certificates \
        apt-transport-https \
        lsb-release \
        software-properties-common \
        gnupg \
        gnupg2 \
    && curl -fsSL https://apt.releases.hashicorp.com/gpg | apt-key add - \
    && apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com focal main" \
    && apt-get install -qy --no-install-recommends \
        python3 \
        python3-distutils \
        python3-dev \
        python3-pip \
        unzip \
        gzip \
        tar \
        jq \
        terraform \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /tmp/* /var/lib/apt/lists/* \
    && python3 -m pip install --disable-pip-version-check --progress-bar off -U pip
    && python3 -m pip install --disable-pip-version-check --progress-bar off -U -r requirements-ci.txt

VOLUME [ "/etc/gitlab-runner" ]
