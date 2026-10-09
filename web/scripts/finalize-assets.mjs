import { copyFile, readdir, readFile, unlink } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const output = fileURLToPath(new URL('../../app/static/ui/', import.meta.url))
const htmlPath = join(output, 'index.html')
const html = await readFile(htmlPath, 'utf8')
const stylesheet = html.match(/href="\/static\/ui\/([^" ]+\.css)"/)
if (!stylesheet) throw new Error('Vite build did not emit its application stylesheet.')
await copyFile(join(output, stylesheet[1]), join(output, 'style.css'))
await unlink(htmlPath)
for (const name of await readdir(output)) {
  if (name.endsWith('.css') && name !== 'style.css') await unlink(join(output, name))
}
