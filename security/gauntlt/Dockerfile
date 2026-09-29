# Image Gauntlt (Ruby 2.7 + nmap + curl) utilisée par le stage SECURITY TESTS - GAUNTLT
FROM ruby:2.7

RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap \
 && rm -rf /var/lib/apt/lists/*

# Versions compatibles Ruby 2.7 (les dernières exigent Ruby >= 3.2)
RUN gem install nokogiri -v 1.15.7 --no-document \
 && gem install multi_json -v 1.15.0 --no-document \
 && gem install gauntlt -v 1.0.13 --no-document

WORKDIR /tmp/attacks
CMD ["gauntlt", "--help"]
