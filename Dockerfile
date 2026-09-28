FROM eclipse-temurin:17-jre-jammy

WORKDIR /app

# Utilisateur non-root (bonne pratique sécurité, recommandée par trivy config)
RUN groupadd --system app && useradd --system --gid app --no-create-home app

COPY --chown=app:app target/timesheet-devops-1.0.jar app.jar

USER app

EXPOSE 8082

ENTRYPOINT ["java", "-jar", "app.jar"]
