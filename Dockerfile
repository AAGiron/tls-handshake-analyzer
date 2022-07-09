FROM python:3.10

COPY src/requirements.txt .
RUN pip install -r requirements.txt

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y tshark

COPY src ./src
COPY captures ./captures

WORKDIR src

ENTRYPOINT ["python3", "main.py"]
