import { mount } from "svelte";
import "./app.css";
import App from "./App.svelte";
import { noteSignIn } from "./lib/api";

const target = document.getElementById("app");
if (!target) throw new Error("missing #app");

// Before the router reads the address: take the sign-in mark out of it.
noteSignIn();

export default mount(App, { target });
