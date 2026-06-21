import requests
r = requests.get('https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf')
with open('python_core/test_in.pdf', 'wb') as f:
    f.write(r.content)
print('Downloaded test_in.pdf')
