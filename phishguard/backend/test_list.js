const { GoogleGenerativeAI } = require('@google/generative-ai');
async function test() {
  const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=AIzaSyCXubgtAF2D8hJpRYf5u-qhFmLp--S0P60`);
  const data = await res.json();
  console.log(data);
}
test();
