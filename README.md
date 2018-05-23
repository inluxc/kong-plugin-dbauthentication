# kong-plugin-dbauthentication

This plugin is inspired from the official ldap auth plugin, except it connects to a database to verify credentials.

The plugin was tested against kong:0.12 and mysql-5.6


    # install mysql and create db
    
    sudo apt-get install mysql-server-5.6
    mysql -u root -proot -e "CREATE DATABASE ngx_test";
    mysql -u root -proot -e "CREATE USER 'ngx_user'@'localhost' IDENTIFIED BY 'ngx_pwd';";
    mysql -u root -proot -e "GRANT ALL PRIVILEGES ON ngx_test.* TO 'ngx_user'@'localhost'"
    mysql -u ngx_user -pngx_pwd  -e "CREATE TABLE person(login VARCHAR(30) NOT NULL, pwd VARCHAR(30) NOT NULL);" ngx_test
    mysql -u ngx_user -pngx_pwd  -e "INSERT INTO ngx_test.person(login, pwd) VALUES ('bob', 'bob123');         " ngx_test
    
    # verification
    mysql -u ngx_user -pngx_pwd  -e "select count(1) from person where login = 'bob' and pwd = 'bob123';        " ngx_test
        
    # to run the tests, we need a simple api that simply roots calls to mockbin, using a
    # 'catch-all' setup with the `uris` field set to '/'
    curl -i -X POST \
      --url http://localhost:8001/apis/ \
      --data 'name=mockbin' \
      --data 'upstream_url=http://mockbin.org/request' \
      --data 'uris=/'
    
    # add the dbauthentication plugin, to the mockbin api
    curl -i -X POST \
      --url http://localhost:8001/apis/mockbin/plugins/ \
      --data "name=dbauthentication" \
      --data "config.db_host=localhost" \
      --data "config.db_port=3306" \
      --data "config.db_name=ngx_test" \
      --data "config.db_user=ngx_user" \
      --data "config.db_passwd=ngx_pwd" \
      --data "config.db_user_table=person" \
      --data "config.db_username_column=login" \
      --data "config.db_passwd_column=pwd"
    
    # verify the plugin
    curl -i http://localhost:8000
        
    echo username:password | base64
    dXNlcm5hbWU6cGFzc3dvcmQK
    
    curl -i \
      -H "Authorization: ldap dXNlcm5hbWU6cGFzc3dvcmQK" \
      http://localhost:8000
    
    echo "bob:bob123" | base64
    Ym9iOmJvYjEyMwo=
    
    curl -i \
      -H "Authorization: ldap Ym9iOmJvYjEyMwo=" \
      http://localhost:8000
    
## TODO

    
* verify cache behaviors
* add tests and doc
* how to install easily without vagrant
