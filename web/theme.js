// тема до загрузки стилей, чтобы не мигало: auto | light | dark
(function(){var t;try{t=localStorage.getItem('theme')}catch(e){}
if(t==='light'||t==='dark')document.documentElement.dataset.theme=t;})();
