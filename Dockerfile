FROM eclipse-temurin:17-jdk-jammy
ARG PROJECT_NAME=ma-authorization
ARG SERVER_PORT=8081
ARG MANAGEMENT_SERVER_PORT=18081

ENV APP_HOME /usr/app
ENV DB_MA_PLATFORM_URL jdbc:mysql://172.18.0.3:3306/ma-platform
ENV DB_MA_PLATFORM_USER ma-platform-user
ENV DB_MA_PLATFORM_PASSWORD ma-platform-password
ENV SERVER_PORT ${SERVER_PORT}
ENV MANAGEMENT_SERVER_PORT ${MANAGEMENT_SERVER_PORT}
WORKDIR $APP_HOME
EXPOSE ${SERVER_PORT}
EXPOSE ${MANAGEMENT_SERVER_PORT}
RUN mkdir -p /app/
ADD ./build/libs/${PROJECT_NAME}*.jar ./${PROJECT_NAME}.jar
RUN echo "#!/bin/bash \n java -jar ./${PROJECT_NAME}.jar" > ./entrypoint.sh
RUN chmod +x ./entrypoint.sh
ENTRYPOINT ["./entrypoint.sh"]