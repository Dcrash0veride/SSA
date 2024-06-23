FROM alpine:latest

RUN apk add --no-cache python3 py3-pip git

WORKDIR /usr/app/src

RUN git clone https://github.com/Dcrash0veride/SSA.git .

RUN pip3 install -r requirements.txt --break-system-packages

ENTRYPOINT ["python3", "main.py"]