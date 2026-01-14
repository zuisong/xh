use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use reqwest::{Client, Request, Response};

#[derive(Clone)]
pub struct ResponseMeta {
    pub request_duration: Duration,
    pub content_download_duration: Option<Duration>,
}

pub trait ResponseExt {
    fn meta(&self) -> &ResponseMeta;
    fn meta_mut(&mut self) -> &mut ResponseMeta;
}

impl ResponseExt for Response {
    fn meta(&self) -> &ResponseMeta {
        self.extensions().get::<ResponseMeta>().unwrap()
    }

    fn meta_mut(&mut self) -> &mut ResponseMeta {
        self.extensions_mut().get_mut::<ResponseMeta>().unwrap()
    }
}

type Printer<'a, 'b> = &'a mut (dyn FnMut(&mut Response, &mut Request) -> Result<()> + Send + 'b);

pub struct Context<'a, 'b> {
    client: &'a Client,
    printer: Option<Printer<'a, 'b>>,
    middlewares: &'a mut [Box<dyn Middleware + Send + 'b>],
}

impl<'a, 'b> Context<'a, 'b> {
    fn new(
        client: &'a Client,
        printer: Option<Printer<'a, 'b>>,
        middlewares: &'a mut [Box<dyn Middleware + Send + 'b>],
    ) -> Self {
        Context {
            client,
            printer,
            middlewares,
        }
    }

    async fn execute(&mut self, request: Request) -> Result<Response> {
        match self.middlewares {
            [] => {
                let starting_time = Instant::now();
                let mut response = self.client.execute(request).await?;
                response.extensions_mut().insert(ResponseMeta {
                    request_duration: starting_time.elapsed(),
                    content_download_duration: None,
                });
                Ok(response)
            }
            [ref mut head, tail @ ..] => {
                head.handle(
                    #[allow(clippy::needless_option_as_deref)]
                    Context::new(self.client, self.printer.as_deref_mut(), tail),
                    request,
                )
                .await
            }
        }
    }
}

#[async_trait]
pub trait Middleware: Send {
    async fn handle(&mut self, ctx: Context<'_, '_>, request: Request) -> Result<Response>;

    async fn next(&self, ctx: &mut Context<'_, '_>, request: Request) -> Result<Response> {
        ctx.execute(request).await
    }

    fn print(
        &self,
        ctx: &mut Context<'_, '_>,
        response: &mut Response,
        request: &mut Request,
    ) -> Result<()> {
        if let Some(ref mut printer) = ctx.printer {
            printer(response, request)?;
        }

        Ok(())
    }
}

pub struct ClientWithMiddleware<'a, T>
where
    T: FnMut(&mut Response, &mut Request) -> Result<()>,
{
    client: &'a Client,
    printer: Option<T>,
    middlewares: Vec<Box<dyn Middleware + Send + 'a>>,
}

impl<'a, T> ClientWithMiddleware<'a, T>
where
    T: FnMut(&mut Response, &mut Request) -> Result<()> + Send + 'a,
{
    pub fn new(client: &'a Client) -> Self {
        ClientWithMiddleware {
            client,
            printer: None,
            middlewares: vec![],
        }
    }

    pub fn with_printer(mut self, printer: T) -> Self {
        self.printer = Some(printer);
        self
    }

    pub fn with(mut self, middleware: impl Middleware + Send + 'a) -> Self {
        self.middlewares.push(Box::new(middleware));
        self
    }

    pub async fn execute(&mut self, request: Request) -> Result<Response> {
        let mut ctx = Context::new(
            self.client,
            self.printer.as_mut().map(|p| p as _),
            &mut self.middlewares[..],
        );
        ctx.execute(request).await
    }
}
