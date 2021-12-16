FROM ubuntu:18.04

RUN apt-get update -y && \
    apt-get install -y python-pip python-dev
# We copy just the requirements.txt first to leverage Docker cache
#COPY ./requirements.txt /app/requirements.txt
WORKDIR /app
#RUN pip install -r requirements.txt
RUN pip install flask
RUN pip install requests 
RUN pip install jwt==0.5.2
#RUN pip install 

COPY . /app
CMD [ "python", "./app.py" ]
