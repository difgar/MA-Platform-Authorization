# Zulu con versión exacta, la misma JVM en todos los servicios y corregida contra Java4Shell
# (CVE-2026-114938, corregido en 25.0.5.1). Desde mirror.gcr.io (copia de Docker Hub de
# Google, mismos digests) porque Docker Hub devuelve 429 a Cloud Build. Ubuntu (glibc) en
# vez de alpine: es la base de todos los demás servicios.
FROM mirror.gcr.io/azul/zulu-openjdk:25.0.5.1-jre-headless@sha256:bbe13f92922bb76ebef167028b849400ce8576f53949e93dcd7c603f622e6ca9

ARG PROJECT_NAME=ma-authorization
ENV APP_HOME=/usr/app

WORKDIR $APP_HOME
COPY ./build/libs/${PROJECT_NAME}*.jar ./ma-authorization.jar

# Sin root: la imagen anterior ejecutaba como root con un JDK completo.
RUN groupadd --system app && useradd --system --gid app --no-create-home app \
 && chown -R app:app $APP_HOME
USER app

EXPOSE 8081 18081

# Forma exec, sin envoltorio de bash. El Dockerfile anterior generaba un script
# entrypoint.sh, así que SIGTERM llegaba a bash y no a la JVM: el
# terminationGracePeriodSeconds del deployment no servía de nada.
ENTRYPOINT ["java", "-jar", "/usr/app/ma-authorization.jar"]
