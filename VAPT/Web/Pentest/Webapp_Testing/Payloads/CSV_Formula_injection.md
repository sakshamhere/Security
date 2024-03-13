# when a spreadsheet program which is microsoft excel or Libre office is used to open a CSV, any cells starting with '=' will be interpreted as a formula by software

exaple explooit senerio

- intercept request and change filename parameter with payload =cmd|'/C notepad'!'A1'

- now download the file and we see a popup which means it gets erxecuted successully