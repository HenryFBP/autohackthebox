from typing import Dict

from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement


def is_login_form(form: WebElement) -> bool:
    if 'login' in form.get_attribute('action'):
        return True

    if ('username' in form.text.lower()) or ('password' in form.text.lower()):
        return True

    return False


def determine_form_type(form: WebElement) -> str:
    """
    Use "advanced logic" and "epic facts" to determine what type of form a form is... wew
    :param form: The form.
    :return: What type of form.
    """

    if is_login_form(form):
        return 'login'

    raise NotImplementedError("Not sure what to do for this form: " + repr(form))


def fill_form(form: WebElement, paramMap: Dict[str, str]) -> WebElement:
    for id in paramMap.keys():
        cred = paramMap[id]
        print(id, cred)

        selector = f'//input[@name="{id}"]'
        input_elt: WebElement = form.find_element(By.XPATH, selector)

        print(f"Filled {selector} with {cred}")

        input_elt.send_keys(cred)

    return form


def submit_form(form: WebElement) -> None:
    selector = '//input[@type="submit"]'
    input_elt: WebElement = form.find_element(By.XPATH, selector)
    if input_elt:
        input_elt.click()
        return

    form.submit()  # is this right?