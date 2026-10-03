FROM eclipse-temurin:17-jre-jammy

WORKDIR /app

# Correctifs de sécurité de l'OS (ex. libssl3) publiés après la construction de l'image de base.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Utilisateur non-root (bonne pratique sécurité, recommandée par trivy config)
RUN groupadd --system app && useradd --system --gid app --no-create-home app

COPY --chown=app:app target/timesheet-devops-1.0.jar app.jar

USER app

EXPOSE 8082

ENTRYPOINT ["java", "-jar", "app.jar"]
