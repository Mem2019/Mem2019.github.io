## Manifest

```json
{
    "name": "Getting Started Example",
    "version": "1.0",
    "description": "Build an Extension!",
    "permissions": ["activeTab","declarativeContent","storage"],
    "background": { 
    // set backgroud script, which will be executed when loaded
      "scripts": ["background.js"],
      "persistent": false
    },
    "page_action": {
      "default_popup": "popup.html",
      "default_icon": {
        "16": "images/get_started16.png",
        "32": "images/get_started32.png",
        "48": "images/get_started48.png",
        "128": "images/get_started128.png"
      }
    },
    "icons": {
      "16": "images/get_started16.png",
      "32": "images/get_started32.png",
      "48": "images/get_started48.png",
      "128": "images/get_started128.png"
    },
    "manifest_version": 2
  }
```

## Backgroud Script

```javascript
chrome.runtime.onInstalled.addListener(function(){...})
chrome.storage.sync.set({x:123}, function() {.../*success callback*/})
//"permissions": ["storage"]
```

## Popup

```json
 "page_action": {
      "default_popup": "popup.html",
     "default_icon"
    },
"icons"


```

```javascript
chrome.declarativeContent.onPageChanged.removeRules(undefined, function()
	{
		chrome.declarativeContent.onPageChanged.addRules([
		{
			conditions: [new chrome.declarativeContent.PageStateMatcher(
			{
				pageUrl: {hostEquals: 'developer.chrome.com'},
			})//only active in this page
			],
			actions: [new chrome.declarativeContent.ShowPageAction()]
		}]);
	});//"declarativeContent" permission
```

```javascript
chrome.storage.sync.get('color', function(data) {
    //use data.color;
  });
```

## Interact with Page

```javascript
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      chrome.tabs.executeScript(
          tabs[0].id,
          {code: 'document.body.style.backgroundColor = "' + color + '";'});
    });//"activeTab" permission
```

## Option

```json
"options_page": "options.html",
```

