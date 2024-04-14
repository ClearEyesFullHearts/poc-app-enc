<script setup>
import { ref } from 'vue'
import { fetchWrapper } from '../lib/fetchHelper';

const props = defineProps({
  msg: String,
});

const title = ref('Vite + Vue');

async function login() {
  const time = Date.now();
  const body = {
    username: 'test@example.com',
    password: 'aaaaaaaa',
  };

  const res = await fetchWrapper.login('/login', body);

  const resBody = await res.json();
  console.log('response body', resBody);

  title.value = resBody.username;
  count.value = Date.now() - time;
}

const count = ref(0)
</script>

<template>
  <h1>{{ title }}</h1>

  <div class="card">
    <button type="button" @click="login()">count is {{ count }}</button>
    <p>
      Edit
      <code>components/HelloWorld.vue</code> to test HMR
    </p>
  </div>

  <p>
    Check out
    <a href="https://vuejs.org/guide/quick-start.html#local" target="_blank"
      >create-vue</a
    >, the official Vue + Vite starter
  </p>
  <p>
    Install
    <a href="https://github.com/vuejs/language-tools" target="_blank">Volar</a>
    in your IDE for a better DX
  </p>
  <p class="read-the-docs">Click on the Vite and Vue logos to learn more</p>
</template>

<style scoped>
.read-the-docs {
  color: #888;
}
</style>
