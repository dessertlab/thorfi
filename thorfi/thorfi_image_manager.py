
def create_thorfi_image(glance_client, thorfi_image_name, thorfi_image_path):
    
    image = glance_client.images.create(name=thorfi_image_name, disk_format='qcow2', container_format='bare')
    glance_client.images.upload(image.id, open(thorfi_image_path, 'rb'))

    return image


def get_thorfi_image(glance_client, thorfi_image_name):

    images_list = glance_client.images.list()
    images_name_list = []
    images = {}

    for image in images_list:
        images[image['name']] = image['id']
        images_name_list.append(image['name'])

    if thorfi_image_name not in images_name_list:
        
        # thorfi_vm_image is not created...create it
        return None

    else:
        return images[thorfi_image_name]
