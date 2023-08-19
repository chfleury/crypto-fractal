
const axios = require("axios");

axios
  .get("https://sigaa.unb.br/sigaa/public/turmas/listar.jsf")
  .then(function (response) {
    const cookie = response.headers["set-cookie"][0].split(";")[0];

    axios
      .post(
        "https://sigaa.unb.br/sigaa/public/turmas/listar.jsf",
        "formTurma=formTurma&formTurma%3AinputNivel=G&formTurma%3AinputDepto=673&formTurma%3AinputAno=2023&formTurma%3AinputPeriodo=1&formTurma%3Aj_id_jsp_1370969402_11=Buscar&javax.faces.ViewState=j_id1",
        {
          headers: {
            Host: "sigaa.unb.br",
            "User-Agent":
              "Mozilla/5.0 (X11; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0",
            Accept:
              "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "194",
            Origin: "https://sigaa.unb.br",
            Referer: "https://sigaa.unb.br/sigaa/public/turmas/listar.jsf",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            Cookie: cookie,
          },
        }
      )
      .then(function (response) {
        const materia = response.data.split("FGA0211")[1].split("FGA0214")[0];

        const regex = new RegExp(
          /<td style="text-align: center;">([0-9]+)<\/td>/g
        );

        let match = regex.exec(materia);
        const qntVagas = Number(match[1]);

        match = regex.exec(materia);
        const vagasOcupadas = Number(match[1]);

        console.log(Boolean(qntVagas - vagasOcupadas));
        console.log('Quantidade de vagas: ',qntVagas, 'Quantidade de vagas ocupadas:', vagasOcupadas)
      })
      .catch(function (response) {
        console.log(response);
      });
  });
