FROM nginx:alpine
RUN apk add --no-cache bash curl tzdata gettext jq
ENV TZ=Asia/Shanghai
COPY scripts/ /scripts/
RUN sed -i 's/\r$//' /scripts/*.sh && chmod +x /scripts/*.sh
COPY nginx/ /etc/nginx/templates-src/
RUN mkdir -p /etc/nginx/subscribe /var/log/subscribe
EXPOSE 80 443
ENTRYPOINT ["/scripts/entrypoint.sh"]
