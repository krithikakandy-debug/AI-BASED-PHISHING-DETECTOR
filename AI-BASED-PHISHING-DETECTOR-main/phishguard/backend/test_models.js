const { GoogleGenerativeAI } = require('@google/generative-ai');
const genAI = new GoogleGenerativeAI("AIzaSyCXubgtAF2D8hJpRYf5u-qhFmLp--S0P60");

async function test() {
  try {
    const model = genAI.getGenerativeModel({ model: "gemini-pro" });
    const result = await model.generateContent("hello");
    console.log("gemini-pro OK", await result.response.text());
  } catch(e) { console.error("gemini-pro failed", e.message); }
}
test();
