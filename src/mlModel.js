const tf = require('@tensorflow/tfjs');

let model;

async function createModel() {
  model = tf.sequential();

  model.add(tf.layers.dense({ units: 16, inputShape: [6], activation: 'relu' }));
  model.add(tf.layers.dense({ units: 8, activation: 'relu' }));
  model.add(tf.layers.dense({ units: 1, activation: 'sigmoid' }));

  model.compile({
    optimizer: 'adam',
    loss: 'binaryCrossentropy',
    metrics: ['accuracy']
  });

  return model;
}

module.exports = { createModel };