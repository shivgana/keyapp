FROM ubuntu

RUN apt-get update -y && \
    apt-get install -y python-pip python-dev
# We copy just the requirements.txt first to leverage Docker cache
#COPY ./requirements.txt /app/requirements.txt
WORKDIR /app
#RUN pip install -r requirements.txt
RUN pip install flask
RUN pip install keycloak==3.0.1

COPY . /app
CMD [ "python", "./app.py" ]
