FROM python:alpine

#RUN apt-get update -y && \
#    apt-get install -y python-pip python-dev
# We copy just the requirements.txt first to leverage Docker cache
#COPY ./requirements.txt /app/requirements.txt
WORKDIR /app
#RUN pip install -r requirements.txt
RUN pip install flask
RUN pip install requests 
RUN pip install PyJWT
#RUN pip install 
EXPOSE 5000
COPY . /app
#CMD [ "python", "./app.py" ]
ENV FLASK_APP=app
CMD ["flask","run", "--host=0.0.0.0" ,"--port=5000"]
