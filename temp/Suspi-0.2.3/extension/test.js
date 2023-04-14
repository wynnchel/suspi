const vscode = require('vscode');
const axios = require('axios');

const requests = [
  axios.get('https://api.example.com/data/1'),
  axios.get('https://api.example.com/data/2'),
  axios.get('https://api.example.com/data/3')
];

Promise.all(requests.map(promise => promise.then(response => response.data)))
  .then(dataArray => {
    // Do something with the array of data
    console.log(dataArray);
  })
  .catch(error => {
    // Handle errors
    console.error(error);
  });