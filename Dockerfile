FROM azul/zulu-openjdk:17-jre-headless
ARG PROJECT_NAME=ma-authorization
ARG SERVER_PORT=8081
ARG MANAGEMENT_SERVER_PORT=18081

ENV APP_HOME /usr/app
ENV APP_JAR ${PROJECT_NAME}.jar
ENV DB_MA_PLATFORM_URL jdbc:mysql://172.18.0.3:3306/ma-platform
ENV DB_MA_PLATFORM_USER ma-platform-user
ENV DB_MA_PLATFORM_PASSWORD ma-platform-password
ENV SERVER_PORT ${SERVER_PORT}
ENV MANAGEMENT_SERVER_PORT ${MANAGEMENT_SERVER_PORT}
WORKDIR $APP_HOME
EXPOSE ${SERVER_PORT}
EXPOSE ${MANAGEMENT_SERVER_PORT}
ADD ./build/libs/${PROJECT_NAME}*.jar ./${APP_JAR}
# Se conserva una shell para expandir $APP_HOME y $APP_JAR, pero con exec: asi la
# JVM es PID 1, recibe SIGTERM y el terminationGracePeriodSeconds del pod sirve
# de algo. El entrypoint.sh anterior la lanzaba como hijo de bash sin exec.
ENTRYPOINT ["/bin/sh", "-c", "exec java -jar $APP_HOME/$APP_JAR"]
