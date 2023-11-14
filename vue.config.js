// const { defineConfig } = require('@vue/cli-service')
// module.exports = defineConfig({
//   transpileDependencies: true
// })
export const publicPath = process.env.NODE_ENV === 'production'
  ? '/CRUD/'
  : '/';