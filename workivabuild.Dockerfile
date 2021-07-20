FROM golang:1.15-alpine as go-build
ARG BUILD_ID
ARG BUILD_NUMBER
ARG BUILD_URL
ARG GIT_COMMIT
ARG GIT_BRANCH
ARG GIT_TAG
ARG GIT_COMMIT_RANGE
ARG GIT_HEAD_URL
ARG GIT_MERGE_HEAD
ARG GIT_SSH_KEY
ARG KNOWN_HOSTS_CONTENT

WORKDIR /build/
ADD . /build/

## Github Credentials
RUN apk add --update bash curl git openssh py-pip gcc musl-dev
ARG GIT_SSH_KEY
RUN git config --global url.git@github.com:.insteadOf https://github.com/
RUN mkdir ~/.ssh; ssh-keyscan -t rsa github.com > ~/.ssh/known_hosts
RUN chmod -R 700 ~/.ssh; echo "${GIT_SSH_KEY}" > ~/.ssh/id_rsa; chmod 600 ~/.ssh/id_rsa
RUN eval "$(ssh-agent -s)" && ssh-add ~/.ssh/id_rsa

# Install Dependencies
RUN apk add --update make

# Build
RUN go install -buildmode=shared -linkshared std
RUN go install -buildmode=shared -linkshared github.com/Workiva/ssllabs-go/v3
RUN go build github.com/Workiva/ssllabs-go/v3

FROM scratch
