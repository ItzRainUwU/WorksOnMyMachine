// These imports intentionally disagree with the filenames on disk.
import { renderNavigation } from "./components/navbar.js";
import { request } from "./lib/apiClient.js";

console.log(renderNavigation(), request("/health"));
