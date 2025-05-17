import aiofiles
import uuid

async def save_temp_file(file):
    temp_path = f"/tmp/{uuid.uuid4()}_{file.filename}"
    async with aiofiles.open(temp_path, 'wb') as out_file:
        content = await file.read()
        await out_file.write(content)
    return temp_path