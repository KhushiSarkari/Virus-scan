// import { execSync } from "child_process";
import { writeFile, unlinkSync, existsSync, mkdirSync, writeFileSync } from "fs";
import { options } from './options';
import NodeClam from 'clamscan';


module.exports.virusScan = async (event, context) => {
    const { file, fileName } = event.body;

    console.log(fileName);
    if (!existsSync(`${__dirname}/tmp/`)) {
        await mkdirSync(`${__dirname}/tmp/`);
    }
    await writeFileSync(`${__dirname}/tmp/${fileName}`, file, { encoding: 'base64' });
    try {
        const clamscan = await new NodeClam().init(options);
        const { isInfected, file, viruses } = await clamscan.isInfected(`${__dirname}/tmp/${fileName}`);
        if (isInfected) console.log(`${file} is infected: ${viruses}!`);
        await unlinkSync(`${__dirname}/tmp/${fileName}`);
        return {
            statusCode: 200,
            body: JSON.stringify({ message: `is file infected: ${isInfected}` }),
        }

    } catch (err) {
        await unlinkSync(`${__dirname}/tmp/${fileName}`);
        console.log(err);
        return {
            statusCode: 400,
            data: JSON.stringify({ message: err })
        }
    }
}