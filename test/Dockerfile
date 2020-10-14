FROM debian:9.0

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt-get install -y python3 python3-venv python3-pip nmap sudo
RUN mkdir /home/recrutement_synacktiv
WORKDIR /home/recrutement_synacktiv
COPY . .
COPY test/config.json config.json
RUN chmod +x ./test/setup.sh && ./test/setup.sh
CMD chmod +x ./test/${TEST_SET}.sh && ./test/${TEST_SET}.sh