FROM eclipse-temurin:25-jre-alpine

ARG PROJECT_NAME=ma-authorization
ENV APP_HOME=/usr/app

WORKDIR $APP_HOME
COPY ./build/libs/${PROJECT_NAME}*.jar ./ma-authorization.jar

# Sin root: la imagen anterior ejecutaba como root con un JDK completo.
RUN addgroup -S app && adduser -S -G app app && chown -R app:app $APP_HOME
USER app

EXPOSE 8081 18081

# Forma exec, sin envoltorio de bash. El Dockerfile anterior generaba un script
# entrypoint.sh, así que SIGTERM llegaba a bash y no a la JVM: el
# terminationGracePeriodSeconds del deployment no servía de nada.
ENTRYPOINT ["java", "-jar", "/usr/app/ma-authorization.jar"]
